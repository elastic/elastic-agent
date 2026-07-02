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
// forwards them as a single ConsumeLogs call.
func (c *monitoringConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().Attributes().PutStr("elastic.mapping.mode", "bodymap")

	now := time.Now()

	var beatEvents []mapstr.M
	beatEvents = append(beatEvents, buildExporterEvents(c.logger, c.config, md)...)
	beatEvents = append(beatEvents, buildInputEvents(c.config, md)...)
	beatEvents = append(beatEvents, buildReceiverPipelineEvents(c.config, md)...)

	for _, beatEvent := range beatEvents {
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

// buildExporterEvents builds one Beats-format monitoring event per exporter
// reporting metrics in md, using cfg.EventTemplate for static fields and
// cfg.ExporterNames to resolve the agent component name.
func buildExporterEvents(logger *zap.Logger, cfg *Config, md pmetric.Metrics) []mapstr.M {
	exporterMetricsMap := convertScopeMetrics(md)
	events := make([]mapstr.M, 0, len(exporterMetricsMap))
	for exporter, metrics := range exporterMetricsMap {
		componentID, ok := cfg.ExporterNames[exporter]
		if !ok {
			logger.Warn("Reporting metrics for exporter with no specified component name", zap.String("exporter_id", exporter))
			componentID = exporter
		}
		beatEvent := mapstr.M(cfg.EventTemplate.Fields).Clone()
		addMetricsToEventFields(logger, metrics, &beatEvent)
		_, _ = beatEvent.Put("component.id", componentID)
		events = append(events, beatEvent)
	}
	return events
}

// buildInputEvents builds one Beats-format monitoring event per filebeat input
// reporting metrics in md, using cfg.InputEventTemplate for static fields.
func buildInputEvents(cfg *Config, md pmetric.Metrics) []mapstr.M {
	var events []mapstr.M
	for compID, compData := range collectComponentInputMetrics(md) {
		if compData.beatType != "filebeat" {
			continue
		}
		for _, inputMetrics := range compData.inputs {
			beatEvent := mapstr.M(cfg.InputEventTemplate.Fields).Clone()
			_, _ = beatEvent.Put("component.id", compID)
			namespace := compData.beatType + "_input"
			for k, v := range inputMetrics {
				_, _ = beatEvent.Put(namespace+"."+k, v)
			}
			events = append(events, beatEvent)
		}
	}
	return events
}

// buildReceiverPipelineEvents builds one Beats-format monitoring event per
// component reporting RegistryBridge pipeline metrics in md, using
// cfg.EventTemplate for static fields.
func buildReceiverPipelineEvents(cfg *Config, md pmetric.Metrics) []mapstr.M {
	receiverPipelineMetrics := collectReceiverMetrics(md)
	events := make([]mapstr.M, 0, len(receiverPipelineMetrics))
	for compID, fields := range receiverPipelineMetrics {
		beatEvent := mapstr.M(cfg.EventTemplate.Fields).Clone()
		_, _ = beatEvent.Put("component.id", compID)
		for k, v := range fields {
			_, _ = beatEvent.Put(k, v)
		}
		events = append(events, beatEvent)
	}
	return events
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
