// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/elastic/beats/v7/libbeat/otel/otelmap"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

type monitoringConnector struct {
	logger   *zap.Logger
	config   *Config
	consumer consumer.Logs
}

func createConnector(
	_ context.Context,
	set connector.Settings,
	baseCfg component.Config,
	next consumer.Logs,
) (connector.Metrics, error) {
	cfg := baseCfg.(*Config)
	return &monitoringConnector{
		logger:   set.Logger,
		config:   cfg,
		consumer: next,
	}, nil
}

func (c *monitoringConnector) Start(_ context.Context, _ component.Host) error { return nil }
func (c *monitoringConnector) Shutdown(_ context.Context) error                { return nil }

func (c *monitoringConnector) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

// ConsumeMetrics converts all monitoring metrics to Beats-format log records and
// forwards them as a single ConsumeLogs call. Batching all records into one call
// avoids per-document blocking in the downstream pipeline (e.g. ES exporter retries).
func (c *monitoringConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().Attributes().PutStr("elastic.mapping.mode", "bodymap")

	now := time.Now()

	exporterMetricsMap := convertScopeMetrics(md)
	for exporter, metrics := range exporterMetricsMap {
		componentID, ok := c.config.ExporterNames[exporter]
		if !ok {
			c.logger.Warn("Reporting metrics for exporter with no specified component name", zap.String("exporter_id", exporter))
			componentID = exporter
		}
		beatEvent := mapstr.M(c.config.EventTemplate.Fields).Clone()
		addMetricsToEventFields(c.logger, metrics, &beatEvent)
		_, _ = beatEvent.Put("component.id", componentID)
		c.appendLogRecord(scopeLogs, beatEvent, now)
	}

	componentMetrics := collectComponentInputMetrics(md)
	for compID, compData := range componentMetrics {
		if compData.beatType != "filebeat" {
			continue
		}
		for _, inputMetrics := range compData.inputs {
			beatEvent := mapstr.M(c.config.InputEventTemplate.Fields).Clone()
			_, _ = beatEvent.Put("component.id", compID)
			namespace := compData.beatType + "_input"
			for k, v := range inputMetrics {
				_, _ = beatEvent.Put(namespace+"."+k, v)
			}
			c.appendLogRecord(scopeLogs, beatEvent, now)
		}
	}

	receiverPipelineMetrics := collectReceiverMetrics(md)
	for compID, fields := range receiverPipelineMetrics {
		beatEvent := mapstr.M(c.config.EventTemplate.Fields).Clone()
		_, _ = beatEvent.Put("component.id", compID)
		for k, v := range fields {
			_, _ = beatEvent.Put(k, v)
		}
		c.appendLogRecord(scopeLogs, beatEvent, now)
	}

	if pLogs.LogRecordCount() == 0 {
		return nil
	}

	if err := c.consumer.ConsumeLogs(ctx, pLogs); err != nil {
		c.logger.Error("error sending internal telemetry log records", zap.Error(err))
	}
	return nil
}

func (c *monitoringConnector) appendLogRecord(scopeLogs plog.ScopeLogs, beatEvent mapstr.M, now time.Time) {
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	beatEvent["@timestamp"] = now
	timestamp := pcommon.NewTimestampFromTime(now)
	logRecord.SetTimestamp(timestamp)
	logRecord.SetObservedTimestamp(timestamp)

	if val, _ := beatEvent.GetValue("data_stream"); val != nil {
		for _, subField := range []string{"dataset", "namespace", "type"} {
			value, err := beatEvent.GetValue("data_stream." + subField)
			if vStr, ok := value.(string); ok && err == nil {
				logRecord.Attributes().PutStr("data_stream."+subField, vStr)
			}
		}
	}

	if err := otelmap.FromMapstr(logRecord.Body().SetEmptyMap(), beatEvent); err != nil {
		c.logger.Error("couldn't convert map to plog.Log, some fields might be missing", zap.Error(err))
	}
}
