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
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

func newTestConnector(sink *consumertest.LogsSink) *monitoringConnector {
	return &monitoringConnector{
		logger:   zap.NewNop(),
		config:   &Config{},
		consumer: sink,
	}
}

// TestConsumeMetrics_SingleBatchedConsumeLogsCall verifies that all monitoring
// events derived from one ConsumeMetrics call (exporter, input, and receiver
// pipeline metrics) are forwarded in a single ConsumeLogs call rather than one
// call per event.
func TestConsumeMetrics_SingleBatchedConsumeLogsCall(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 100)

	appendScopeToMetrics(md, fbreceiverScopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, "filebeatreceiver/_agent-component/filebeat-default",
	)
	inputSM := md.ResourceMetrics().At(0).ScopeMetrics().At(1)
	appendGaugeIntWithAttrs(inputSM, "beat.input.events.published", 42, otelInputIDKey, "logs.my-input")

	registrySM := appendScopeToMetrics(md, registryBridgeScopeName)
	appendSumIntWithAttrs(registrySM, "libbeat.output.events.acked", 7, registryBridgeReceiverKey, "filebeatreceiver/_agent-component/filestream-default")

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)
	c.config.ExporterNames = map[string]string{exporterID: "monitoring"}

	require.NoError(t, c.ConsumeMetrics(t.Context(), md))

	assert.Len(t, sink.AllLogs(), 1, "expected exactly one ConsumeLogs call, all events should be batched together")
	assert.Equal(t, 3, sink.LogRecordCount(), "expected one log record per generated monitoring event")
}

// TestConsumeMetrics_NoData verifies that ConsumeMetrics doesn't call
// ConsumeLogs at all when there's nothing to report, rather than sending an
// empty batch.
func TestConsumeMetrics_NoData(t *testing.T) {
	md, _ := newMetricsWithScope("some.unrelated.scope")

	sink := &consumertest.LogsSink{}
	c := newTestConnector(sink)

	require.NoError(t, c.ConsumeMetrics(context.Background(), md))

	assert.Empty(t, sink.AllLogs())
}

// eventValue looks up a dotted field path in a Beats-format event, the same
// way mapstr.M.Put interprets the paths used to build these events.
func eventValue(t *testing.T, event mapstr.M, key string) any {
	t.Helper()
	val, err := event.GetValue(key)
	require.NoError(t, err, "key %q not found in event", key)
	return val
}

func TestBuildExporterEvents(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 100)

	cfg := &Config{ExporterNames: map[string]string{exporterID: "monitoring"}}

	events := buildExporterEvents(zap.NewNop(), cfg, md)

	require.Len(t, events, 1)
	assert.Equal(t, "monitoring", eventValue(t, events[0], "component.id"))
	assert.Equal(t, int64(100), eventValue(t, events[0], "beat.stats.libbeat.pipeline.queue.max_events"))
}

func TestBuildExporterEvents_UnknownExporterFallsBackToExporterID(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 1)

	events := buildExporterEvents(zap.NewNop(), &Config{}, md)

	require.Len(t, events, 1)
	assert.Equal(t, exporterID, eventValue(t, events[0], "component.id"))
}

func TestBuildInputEvents(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", 42, otelInputIDKey, "logs.my-input")

	events := buildInputEvents(&Config{}, md)

	require.Len(t, events, 1)
	assert.Equal(t, "filebeat-default", eventValue(t, events[0], "component.id"))
	assert.Equal(t, int64(42), eventValue(t, events[0], "filebeat_input.beat.input.events.published"))
}

func TestBuildInputEvents_IgnoresNonFilebeatComponents(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(mbreceiverScopeName, "metricbeatreceiver/_agent-component/metricbeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", 1, otelInputIDKey, "some-input")

	events := buildInputEvents(&Config{}, md)

	assert.Empty(t, events)
}

func TestBuildReceiverPipelineEvents(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", 7, registryBridgeReceiverKey, receiverID)

	events := buildReceiverPipelineEvents(&Config{}, md)

	require.Len(t, events, 1)
	assert.Equal(t, "filestream-default", eventValue(t, events[0], "component.id"))
	assert.Equal(t, int64(7), eventValue(t, events[0], "beat.stats.libbeat.output.events.acked"))
}

func TestBuildReceiverPipelineEvents_NoData(t *testing.T) {
	md, _ := newMetricsWithScope("some.unrelated.scope")

	events := buildReceiverPipelineEvents(&Config{}, md)

	assert.Empty(t, events)
}
