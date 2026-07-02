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
// call per event. The downstream ES exporter is slow (network round-trip per
// call), so batching avoids blocking once per component on every cycle.
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

	require.NoError(t, c.ConsumeMetrics(context.Background(), md))

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
