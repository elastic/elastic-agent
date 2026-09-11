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

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

type monitoringConnector struct {
	logger   *zap.Logger
	config   *Config
	consumer consumer.Logs
}

const (
	monitoringFieldComponentID = "component.id"
	monitoringFieldInputID     = "filebeat_input.id"
	monitoringFieldInputType   = "filebeat_input.input"
)

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

// ConsumeMetrics converts pre-processed monitoring metrics (from the
// elasticmonitoringprocessor) to Beats-format log records and forwards them as
// a single ConsumeLogs call.
//
// Each ResourceMetrics in md represents one monitoring event. The event type
// (exporter, input, or receiver) is read from the elastic.monitoring.event.type
// scope attribute on the first ScopeMetrics entry; the appropriate event template
// is cloned and all metrics in the ResourceMetrics are written as fields on the event.
func (c *monitoringConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	pLogs := plog.NewLogs()
	resourceLogs := pLogs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	scopeLogs.Scope().Attributes().PutStr("elastic.mapping.mode", "bodymap")

	now := time.Now()

	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		c.appendMonitoringEvent(scopeLogs, md.ResourceMetrics().At(i), now)
	}

	if pLogs.LogRecordCount() == 0 {
		return nil
	}

	if err := c.consumer.ConsumeLogs(ctx, pLogs); err != nil {
		c.logger.Error("error sending internal telemetry log records", zap.Error(err))
	}
	return nil
}

// appendMonitoringEvent converts one ResourceMetrics event to a log record.
func (c *monitoringConnector) appendMonitoringEvent(scopeLogs plog.ScopeLogs, rm pmetric.ResourceMetrics, now time.Time) {
	if rm.ScopeMetrics().Len() == 0 {
		return
	}
	scopeAttrs := rm.ScopeMetrics().At(0).Scope().Attributes()

	eventTypeVal, ok := scopeAttrs.Get(internaltelemetry.EventTypeAttr)
	if !ok {
		c.logger.Warn("monitoring event missing event type scope attribute, dropping ResourceMetrics")
		return
	}

	var template mapstr.M
	switch eventTypeVal.Str() {
	case internaltelemetry.EventTypeExporter, internaltelemetry.EventTypeReceiver:
		template = mapstr.M(c.config.EventTemplate.Fields).Clone()
	case internaltelemetry.EventTypeInput:
		template = mapstr.M(c.config.InputEventTemplate.Fields).Clone()
	default:
		return
	}

	if compID, ok := scopeAttrs.Get(internaltelemetry.ComponentIDAttr); ok {
		template[monitoringFieldComponentID] = compID.Str()
	}

	eventType := eventTypeVal.Str()
	if eventType == internaltelemetry.EventTypeInput {
		if inputID, ok := scopeAttrs.Get(internaltelemetry.InputIDAttr); ok {
			template[monitoringFieldInputID] = inputID.Str()
		}
		if inputType, ok := scopeAttrs.Get(internaltelemetry.InputTypeAttr); ok {
			template[monitoringFieldInputType] = inputType.Str()
		}
	}

	for j := 0; j < rm.ScopeMetrics().Len(); j++ {
		sm := rm.ScopeMetrics().At(j)
		for k := 0; k < sm.Metrics().Len(); k++ {
			m := sm.Metrics().At(k)
			name := m.Name()
			if val := firstMetricValue(m); val != nil {
				template[name] = val
			}
		}
	}

	c.appendLogRecord(scopeLogs, template, now)
}

// firstMetricValue returns the value of the first data point, or nil if there
// are no data points or the metric type is unsupported.
func firstMetricValue(m pmetric.Metric) any {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		if m.Gauge().DataPoints().Len() > 0 {
			return dataPointNumericValue(m.Gauge().DataPoints().At(0))
		}
	case pmetric.MetricTypeSum:
		if m.Sum().DataPoints().Len() > 0 {
			return dataPointNumericValue(m.Sum().DataPoints().At(0))
		}
	}
	return nil
}

func dataPointNumericValue(dp pmetric.NumberDataPoint) any {
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return dp.IntValue()
	case pmetric.NumberDataPointValueTypeDouble:
		return dp.DoubleValue()
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
