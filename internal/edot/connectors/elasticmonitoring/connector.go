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

func (c *monitoringConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	exporterMetricsMap := convertScopeMetrics(md)
	for exporter, metrics := range exporterMetricsMap {
		componentID, ok := c.config.ExporterNames[exporter]
		if !ok {
			c.logger.Warn("Reporting metrics for exporter with no specified component name", zap.String("exporter_id", exporter))
			componentID = exporter
		}
		c.sendExporterMetricsEvent(ctx, componentID, metrics)
	}

	componentMetrics := collectComponentInputMetrics(md)
	for compID, compData := range componentMetrics {
		if compData.beatType != "filebeat" {
			continue
		}
		for _, inputMetrics := range compData.inputs {
			c.sendInputMetricsEvent(ctx, compID, compData.beatType, inputMetrics)
		}
	}

	receiverPipelineMetrics := collectReceiverMetrics(md)
	for compID, fields := range receiverPipelineMetrics {
		c.sendReceiverPipelineMetricsEvent(ctx, compID, fields)
	}

	return nil
}

func (c *monitoringConnector) sendExporterMetricsEvent(ctx context.Context, componentID string, metrics exporterMetrics) {
	beatEvent := mapstr.M(c.config.EventTemplate.Fields).Clone()
	addMetricsToEventFields(c.logger, metrics, &beatEvent)
	_, _ = beatEvent.Put("component.id", componentID)
	c.sendLogRecord(ctx, beatEvent, componentID)
}

func (c *monitoringConnector) sendReceiverPipelineMetricsEvent(ctx context.Context, componentID string, fields map[string]any) {
	beatEvent := mapstr.M(c.config.EventTemplate.Fields).Clone()
	_, _ = beatEvent.Put("component.id", componentID)
	for k, v := range fields {
		_, _ = beatEvent.Put(k, v)
	}
	c.sendLogRecord(ctx, beatEvent, componentID)
}

func (c *monitoringConnector) sendInputMetricsEvent(ctx context.Context, componentID string, beatType string, inputMetrics map[string]any) {
	beatEvent := mapstr.M(c.config.InputEventTemplate.Fields).Clone()
	_, _ = beatEvent.Put("component.id", componentID)
	namespace := beatType + "_input"
	for k, v := range inputMetrics {
		_, _ = beatEvent.Put(namespace+"."+k, v)
	}
	c.sendLogRecord(ctx, beatEvent, componentID)
}

func (c *monitoringConnector) sendLogRecord(ctx context.Context, beatEvent mapstr.M, componentID string) {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	sourceLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := sourceLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()

	sourceLogs.Scope().Attributes().PutStr("elastic.mapping.mode", "bodymap")

	now := time.Now()
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

	if err := c.consumer.ConsumeLogs(ctx, pLogs); err != nil {
		c.logger.Error("error sending internal telemetry log record", zap.String("component.id", componentID), zap.Error(err))
	}
}
