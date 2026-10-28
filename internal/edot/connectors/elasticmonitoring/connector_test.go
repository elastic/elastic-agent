// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

func newTestConnector(sink *consumertest.LogsSink) *monitoringConnector {
	return &monitoringConnector{
		logger:   zap.NewNop(),
		config:   &Config{},
		consumer: sink,
	}
}

// newProcessorOutputEvent creates a minimal pmetric.Metrics in the format
// produced by the elasticmonitoringprocessor — one ResourceMetrics per event,
// with elastic.monitoring.event.type and component.id as scope attributes.
func newProcessorOutputEvent(eventType, componentID string) pmetric.Metrics {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(internaltelemetry.ScopeName)
	sm.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, eventType)
	sm.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, componentID)
	return md
}

// appendMetricToMD appends a gauge int metric to the first (and only)
// ScopeMetrics inside the first ResourceMetrics of md.
func appendMetricToMD(md pmetric.Metrics, name string, value int64) {
	sm := md.ResourceMetrics().At(0).ScopeMetrics().At(0)
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(value)
}

// TestConsumeMetrics_SingleBatchedConsumeLogsCall verifies that all monitoring
// events (one per ResourceMetrics) are forwarded in a single ConsumeLogs call
// rather than one call per event.
func TestConsumeMetrics_SingleBatchedConsumeLogsCall(t *testing.T) {
	md := pmetric.NewMetrics()

	// Exporter event
	sm1 := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm1.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, internaltelemetry.EventTypeExporter)
	sm1.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, "monitoring")

	// Input event
	sm2 := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm2.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, internaltelemetry.EventTypeInput)
	sm2.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, "filebeat-default")
	sm2.Scope().Attributes().PutStr(internaltelemetry.InputIDAttr, "logs.my-input")

	// Receiver event
	sm3 := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm3.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, internaltelemetry.EventTypeReceiver)
	sm3.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, "filestream-default")

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	require.NoError(t, c.ConsumeMetrics(t.Context(), md))

	assert.Len(t, sink.AllLogs(), 1, "expected exactly one ConsumeLogs call")
	assert.Equal(t, 3, sink.LogRecordCount(), "expected one log record per event")
}

// TestConsumeMetrics_NoData verifies that ConsumeMetrics does not call ConsumeLogs
// when no ResourceMetrics carry a recognised event type.
func TestConsumeMetrics_NoData(t *testing.T) {
	md := pmetric.NewMetrics()
	md.ResourceMetrics().AppendEmpty() // no elastic.monitoring.event.type attribute

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	require.NoError(t, c.ConsumeMetrics(context.Background(), md))

	assert.Empty(t, sink.AllLogs())
}

// TestConsumeMetrics_ExporterEventFields verifies that an exporter event sets the
// component.id field and metric values on the log record body.
func TestConsumeMetrics_ExporterEventFields(t *testing.T) {
	md := newProcessorOutputEvent(internaltelemetry.EventTypeExporter, "my-output")
	appendMetricToMD(md, "beat.stats.libbeat.pipeline.queue.max_events", 1000)

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	c.config.EventTemplate.Fields = map[string]any{
		"data_stream": map[string]any{"dataset": "elastic_agent.elastic_agent"},
	}
	require.NoError(t, c.ConsumeMetrics(t.Context(), md))

	require.Equal(t, 1, sink.LogRecordCount())
	body := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map()

	compID, err := mapstr.M(body.AsRaw()).GetValue("component.id")
	require.NoError(t, err)
	assert.Equal(t, "my-output", compID)

	queueMax, ok := body.Get("beat.stats.libbeat.pipeline.queue.max_events")
	require.True(t, ok)
	assert.Equal(t, int64(1000), queueMax.Int())
}

// TestConsumeMetrics_ComponentIDReplacesTemplateValue verifies that the event's
// component.id overrides the template's nested one instead of adding a second value.
func TestConsumeMetrics_ComponentIDReplacesTemplateValue(t *testing.T) {
	for _, eventType := range []string{
		internaltelemetry.EventTypeExporter,
		internaltelemetry.EventTypeReceiver,
		internaltelemetry.EventTypeInput,
	} {
		t.Run(eventType, func(t *testing.T) {
			template := map[string]any{
				"component": map[string]any{
					"binary": "elastic-otel-collector",
					"id":     "elastic-otel-collector",
				},
			}
			sink := &consumertest.LogsSink{}
			c := newTestConnector(sink)
			c.config.EventTemplate.Fields = template
			c.config.InputEventTemplate.Fields = template
			require.NoError(t, c.ConsumeMetrics(t.Context(), newProcessorOutputEvent(eventType, "filestream-default")))

			require.Equal(t, 1, sink.LogRecordCount())
			body := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map()
			assert.Equal(t, mapstr.M{
				"binary": "elastic-otel-collector",
				"id":     "filestream-default",
			}, mapstr.M(body.AsRaw()["component"].(map[string]any)))
			_, flat := body.Get("component.id")
			assert.False(t, flat, "component.id must not also be set as a flat key")
			assert.Equal(t, "elastic-otel-collector", template["component"].(map[string]any)["id"],
				"the configured template must not be modified")
		})
	}
}

// TestConsumeMetrics_InputEventFields verifies that an input event sets the
// filebeat_input.* fields from resource attributes and metrics.
func TestConsumeMetrics_InputEventFields(t *testing.T) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, internaltelemetry.EventTypeInput)
	sm.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, "filebeat-default")
	sm.Scope().Attributes().PutStr(internaltelemetry.InputIDAttr, "logs.my-input")
	sm.Scope().Attributes().PutStr(internaltelemetry.InputTypeAttr, "log")
	m := sm.Metrics().AppendEmpty()
	m.SetName("filebeat_input.beat.input.events.published")
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(42)

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	require.NoError(t, c.ConsumeMetrics(t.Context(), md))

	require.Equal(t, 1, sink.LogRecordCount())
	body := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map()

	inputID, ok := body.Get("filebeat_input.id")
	require.True(t, ok)
	assert.Equal(t, "logs.my-input", inputID.Str())

	inputType, ok := body.Get("filebeat_input.input")
	require.True(t, ok)
	assert.Equal(t, "log", inputType.Str())

	published, ok := body.Get("filebeat_input.beat.input.events.published")
	require.True(t, ok)
	assert.Equal(t, int64(42), published.Int())
}

// TestConsumeMetrics_EventTemplateApplied verifies that fields from the event
// template appear in the log record body.
func TestConsumeMetrics_EventTemplateApplied(t *testing.T) {
	md := newProcessorOutputEvent(internaltelemetry.EventTypeReceiver, "filestream-default")

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	c.config.EventTemplate.Fields = map[string]any{
		"elastic_agent": map[string]any{"version": "9.0.0"},
	}
	require.NoError(t, c.ConsumeMetrics(t.Context(), md))

	require.Equal(t, 1, sink.LogRecordCount())
	body := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map()

	elasticAgent, ok := body.Get("elastic_agent")
	require.True(t, ok, "elastic_agent field must be present from event template")
	version, ok := elasticAgent.Map().Get("version")
	require.True(t, ok)
	assert.Equal(t, "9.0.0", version.Str())
}
