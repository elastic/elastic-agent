// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

const (
	fbreceiverScopeName = "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	mbreceiverScopeName = "github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"
)

// newMetrics returns a Metrics with one ResourceMetrics and one ScopeMetrics
// pre-configured with the given scope name and attributes (key-value pairs).
func newMetricsWithScope(scopeName string, attrs ...string) (pmetric.Metrics, pmetric.ScopeMetrics) {
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(scopeName)
	for i := 0; i+1 < len(attrs); i += 2 {
		sm.Scope().Attributes().PutStr(attrs[i], attrs[i+1])
	}
	return md, sm
}

func newMetricsWithExporterScope(exporterID string) (pmetric.Metrics, pmetric.ScopeMetrics) {
	return newMetricsWithScope(
		"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter",
		otelComponentKindKey, "exporter",
		otelComponentIDKey, exporterID,
	)
}

func newMetricsWithReceiverScope(scopeName, receiverID string) (pmetric.Metrics, pmetric.ScopeMetrics) {
	return newMetricsWithScope(scopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, receiverID,
	)
}

func newMetricsWithRegistryBridgeScope() (pmetric.Metrics, pmetric.ScopeMetrics) {
	return newMetricsWithScope(registryBridgeScopeName)
}

// appendScopeToMetrics adds an additional ScopeMetrics to an existing Metrics value,
// reusing the first (and only) ResourceMetrics.
func appendScopeToMetrics(md pmetric.Metrics, scopeName string, attrs ...string) pmetric.ScopeMetrics {
	sm := md.ResourceMetrics().At(0).ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(scopeName)
	for i := 0; i+1 < len(attrs); i += 2 {
		sm.Scope().Attributes().PutStr(attrs[i], attrs[i+1])
	}
	return sm
}

func appendGaugeInt(sm pmetric.ScopeMetrics, name string, value int64) {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(value)
}

func appendSumInt(sm pmetric.ScopeMetrics, name string, values ...int64) {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	g := m.SetEmptySum()
	for _, v := range values {
		g.DataPoints().AppendEmpty().SetIntValue(v)
	}
}

func appendGaugeIntWithAttrs(sm pmetric.ScopeMetrics, name string, value int64, kvs ...string) {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(value)
	for i := 0; i+1 < len(kvs); i += 2 {
		dp.Attributes().PutStr(kvs[i], kvs[i+1])
	}
}

func appendSumIntWithAttrs(sm pmetric.ScopeMetrics, name string, value int64, kvs ...string) {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	dp := m.SetEmptySum().DataPoints().AppendEmpty()
	dp.SetIntValue(value)
	for i := 0; i+1 < len(kvs); i += 2 {
		dp.Attributes().PutStr(kvs[i], kvs[i+1])
	}
}

func appendGaugeFloat64WithAttrs(sm pmetric.ScopeMetrics, name string, value float64, kvs ...string) {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetDoubleValue(value)
	for i := 0; i+1 < len(kvs); i += 2 {
		dp.Attributes().PutStr(kvs[i], kvs[i+1])
	}
}

func TestConvertAllMetrics(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	const (
		queueCapacity = int64(1000)
		queueSize     = int64(500)
		sentLogs      = int64(1)
		sentSpans     = int64(2)
		sentMetrics   = int64(3)
		failedLogs    = int64(4)
		failedSpans   = int64(5)
		failedMetrics = int64(6)
		docsProcessed = int64(100)
		docsRetried   = int64(8)
		bulkRequests  = int64(9)
		flushedBytes  = int64(10)
	)

	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, queueCapacity)
	appendGaugeInt(sm, otelQueueSizeKey, queueSize)
	appendSumInt(sm, otelSentLogsKey, sentLogs)
	appendSumInt(sm, otelSentSpansKey, sentSpans)
	appendSumInt(sm, otelSentMetricsKey, sentMetrics)
	appendSumInt(sm, otelFailedLogsKey, failedLogs)
	appendSumInt(sm, otelFailedSpansKey, failedSpans)
	appendSumInt(sm, otelFailedMetricsKey, failedMetrics)
	appendSumInt(sm, otelDocsProcessedKey, docsProcessed)
	appendSumInt(sm, otelDocsRetriedKey, docsRetried)
	appendSumInt(sm, otelFlushedBytesKey, flushedBytes)
	appendSumInt(sm, otelBulkRequestsKey, bulkRequests)

	result := convertScopeMetrics(md)
	assert.Equal(t, 1, len(result), "scope metrics contain one exporter")

	metrics, ok := result[exporterID]
	require.Truef(t, ok, "exporter metrics should contain metrics for id %q", exporterID)

	beatEvent := mapstr.M{}
	addMetricsToEventFields(zap.NewNop(), metrics, &beatEvent)

	maxEvents, err := beatEvent.GetValue(beatsQueueMaxEventsKey)
	assert.NoError(t, err)
	assert.Equal(t, queueCapacity, maxEvents)

	filledEvents, err := beatEvent.GetValue(beatsQueueFilledEventsKey)
	assert.NoError(t, err)
	assert.Equal(t, queueSize, filledEvents)

	filledPct, err := beatEvent.GetValue(beatsQueueFilledPctKey)
	assert.NoError(t, err)
	assert.Equal(t, float64(queueSize)/float64(queueCapacity), filledPct)

	expectedSent := sentLogs + sentSpans + sentMetrics
	eventsAcked, err := beatEvent.GetValue(beatsOutputEventsAckedKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedSent, eventsAcked)

	expectedFailed := failedLogs + failedSpans + failedMetrics
	eventsDropped, err := beatEvent.GetValue(beatsOutputEventsDroppedKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedFailed, eventsDropped)

	eventsTotal, err := beatEvent.GetValue(beatsOutputEventsTotalKey)
	assert.NoError(t, err)
	assert.Equal(t, docsProcessed, eventsTotal)

	eventsFailed, err := beatEvent.GetValue(beatsOutputEventsFailedKey)
	assert.NoError(t, err)
	assert.Equal(t, docsRetried, eventsFailed)

	writeBytes, err := beatEvent.GetValue(beatsOutputWriteBytesKey)
	assert.NoError(t, err)
	assert.Equal(t, flushedBytes, writeBytes)

	expectedActive := docsProcessed - expectedSent - expectedFailed
	active, err := beatEvent.GetValue(beatsOutputEventsActiveKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedActive, active)

	batches, err := beatEvent.GetValue(beatsOutputEventsBatchesKey)
	assert.NoError(t, err)
	assert.Equal(t, bulkRequests, batches)
}

func TestCollectComponentInputMetrics_Basic(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", int64(42), otelInputIDKey, "logs.my-input")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 1)
	compData, ok := result["filebeat-default"]
	require.True(t, ok)
	assert.Equal(t, "filebeat", compData.beatType)
	entry, ok := compData.inputs["logs.my-input"]
	require.True(t, ok)
	assert.Equal(t, "logs.my-input", entry["id"])
	assert.Equal(t, int64(42), entry["beat.input.events.published"])
}

func TestCollectComponentInputMetrics_WithInputType(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", int64(10),
		otelInputIDKey, "my-input", otelInputTypeKey, "log")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 1)
	entry := result["filebeat-default"].inputs["my-input"]
	assert.Equal(t, "log", entry["input"])
}

func TestCollectComponentInputMetrics_DotInInputID(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "some.metric", int64(1), otelInputIDKey, "logs.my-input")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 1)
	inputs := result["filebeat-default"].inputs
	entry, ok := inputs["logs.my-input"]
	require.True(t, ok, "input ID with dots should be used as-is")
	assert.Equal(t, "logs.my-input", entry["id"])
}

func TestCollectComponentInputMetrics_NoInputID(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeInt(sm, "beat.input.events.published", int64(5))

	result := collectComponentInputMetrics(md)
	if compData, ok := result["filebeat-default"]; ok {
		assert.Empty(t, compData.inputs)
	}
}

func TestCollectComponentInputMetrics_MultipleInputsSameComponent(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendSumIntWithAttrs(sm, "beat.input.events.published", int64(7), otelInputIDKey, "input-a")
	appendSumIntWithAttrs(sm, "beat.input.events.published", int64(3), otelInputIDKey, "input-b")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 1)
	inputs := result["filebeat-default"].inputs
	require.Len(t, inputs, 2)
	assert.Equal(t, "input-a", inputs["input-a"]["id"])
	assert.Equal(t, "input-b", inputs["input-b"]["id"])
	assert.Equal(t, int64(7), inputs["input-a"]["beat.input.events.published"])
	assert.Equal(t, int64(3), inputs["input-b"]["beat.input.events.published"])
}

func TestCollectComponentInputMetrics_AcrossScopes(t *testing.T) {
	md, sm1 := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm1, "metric.one", int64(11), otelInputIDKey, "shared-input")

	sm2 := appendScopeToMetrics(md, fbreceiverScopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, "filebeatreceiver/_agent-component/filebeat-default",
	)
	appendGaugeIntWithAttrs(sm2, "metric.two", int64(22), otelInputIDKey, "shared-input")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 1)
	entry := result["filebeat-default"].inputs["shared-input"]
	assert.Equal(t, int64(11), entry["metric.one"])
	assert.Equal(t, int64(22), entry["metric.two"])
}

func TestCollectComponentInputMetrics_DifferentComponents(t *testing.T) {
	md, sm1 := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm1, "beat.input.events.published", int64(10), otelInputIDKey, "input-fb")

	sm2 := appendScopeToMetrics(md, mbreceiverScopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, "metricbeatreceiver/_agent-component/metricbeat-default",
	)
	appendGaugeIntWithAttrs(sm2, "beat.input.events.published", int64(20), otelInputIDKey, "input-mb")

	result := collectComponentInputMetrics(md)
	require.Len(t, result, 2)

	fbData := result["filebeat-default"]
	assert.Equal(t, "filebeat", fbData.beatType)
	require.Len(t, fbData.inputs, 1)
	assert.Equal(t, int64(10), fbData.inputs["input-fb"]["beat.input.events.published"])

	mbData := result["metricbeat-default"]
	assert.Equal(t, "metricbeat", mbData.beatType)
	require.Len(t, mbData.inputs, 1)
	assert.Equal(t, int64(20), mbData.inputs["input-mb"]["beat.input.events.published"])
}

func TestBeatTypeFromOtelID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"filebeatreceiver/_agent-component/filebeat-default", "filebeat"},
		{"metricbeatreceiver/_agent-component/metricbeat-default", "metricbeat"},
		{"elasticsearch/_agent-component/monitoring", "elasticsearch"},
		{"filebeatreceiver/no-agent-component", "filebeat"},
		{"filebeatreceiver", "filebeat"},
		{"somecomponent", "somecomponent"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, beatTypeFromOtelID(tt.input))
		})
	}
}

func TestCollectReceiverPipelineMetrics_Basic(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(3), registryBridgeReceiverKey, receiverID)
	appendSumIntWithAttrs(sm, "pipeline.events.published", int64(42), registryBridgeReceiverKey, receiverID)

	result := collectReceiverMetrics(md)
	require.Len(t, result, 1)
	fields, ok := result["filebeat-default"]
	require.True(t, ok)
	assert.Equal(t, int64(3), fields["beat.stats.filebeat.pipeline.clients"])
	assert.Equal(t, int64(42), fields["beat.stats.filebeat.pipeline.events.published"])
}

func TestCollectReceiverPipelineMetrics_FloatGauge(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeFloat64WithAttrs(sm, "pipeline.queue.filled.pct", float64(0.42), registryBridgeReceiverKey, receiverID)

	result := collectReceiverMetrics(md)
	require.Len(t, result, 1)
	fields := result["filebeat-default"]
	assert.Equal(t, float64(0.42), fields["beat.stats.filebeat.pipeline.queue.filled.pct"])
}

func TestCollectReceiverMetrics_AllMetricsCollected(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "output.events.active", int64(5), registryBridgeReceiverKey, receiverID)
	appendGaugeIntWithAttrs(sm, "harvester.running", int64(3), registryBridgeReceiverKey, receiverID)
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(2), registryBridgeReceiverKey, receiverID)

	result := collectReceiverMetrics(md)
	require.Len(t, result, 1)
	fields := result["filebeat-default"]
	assert.Equal(t, int64(2), fields["beat.stats.filebeat.pipeline.clients"])
	assert.Equal(t, int64(5), fields["beat.stats.filebeat.output.events.active"])
	assert.Equal(t, int64(3), fields["beat.stats.filebeat.harvester.running"])
}

func TestCollectReceiverPipelineMetrics_WrongScopeSkipped(t *testing.T) {
	md, sm := newMetricsWithExporterScope("elasticsearch/_agent-component/monitoring")
	appendGaugeInt(sm, "pipeline.clients", int64(1))

	result := collectReceiverMetrics(md)
	assert.Empty(t, result)
}

func TestCollectReceiverPipelineMetrics_NoReceiverAttr(t *testing.T) {
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeInt(sm, "pipeline.clients", int64(1))

	result := collectReceiverMetrics(md)
	assert.Empty(t, result)
}

func TestCollectReceiverPipelineMetrics_MultipleReceivers(t *testing.T) {
	const fbReceiverID = "filebeatreceiver/_agent-component/filebeat-default"
	const mbReceiverID = "metricbeatreceiver/_agent-component/metricbeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(2), registryBridgeReceiverKey, fbReceiverID)
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(5), registryBridgeReceiverKey, mbReceiverID)

	result := collectReceiverMetrics(md)
	require.Len(t, result, 2)
	assert.Equal(t, int64(2), result["filebeat-default"]["beat.stats.filebeat.pipeline.clients"])
	assert.Equal(t, int64(5), result["metricbeat-default"]["beat.stats.metricbeat.pipeline.clients"])
}

func TestAgentComponentID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"filebeatreceiver/_agent-component/filebeat-default", "filebeat-default"},
		{"elasticsearch/_agent-component/monitoring", "monitoring"},
		{"filebeatreceiver/some-other-prefix", ""},
		{"no-prefix-at-all", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, agentComponentID(tt.input))
		})
	}
}

func TestReceiverMetricField(t *testing.T) {
	tests := []struct {
		beatType   string
		metricName string
		expected   string
	}{
		// libbeat.* names: no beat-type infix
		{"filebeat", "libbeat.output.events.total", "beat.stats.libbeat.output.events.total"},
		{"filebeat", "libbeat.output.events.acked", "beat.stats.libbeat.output.events.acked"},
		// beat-type prefixed names: no double-prefix
		{"filebeat", "filebeat.harvester.running", "beat.stats.filebeat.harvester.running"},
		{"metricbeat", "metricbeat.some.metric", "beat.stats.metricbeat.some.metric"},
		// unqualified names: get beat-type infix
		{"filebeat", "pipeline.clients", "beat.stats.filebeat.pipeline.clients"},
		{"filebeat", "harvester.running", "beat.stats.filebeat.harvester.running"},
	}
	for _, tt := range tests {
		t.Run(tt.beatType+"/"+tt.metricName, func(t *testing.T) {
			assert.Equal(t, tt.expected, receiverMetricField(tt.beatType, tt.metricName))
		})
	}
}

func TestCollectReceiverPipelineMetrics_LibbeatPrefix(t *testing.T) {
	// libbeat.* metric names should NOT get an extra beat-type infix.
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.total", int64(200), registryBridgeReceiverKey, receiverID)
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(180), registryBridgeReceiverKey, receiverID)

	result := collectReceiverMetrics(md)
	require.Len(t, result, 1)
	fields := result["filestream-default"]
	assert.Equal(t, int64(200), fields["beat.stats.libbeat.output.events.total"])
	assert.Equal(t, int64(180), fields["beat.stats.libbeat.output.events.acked"])
	// Confirm the double-prefix form does NOT exist
	assert.Nil(t, fields["beat.stats.filebeat.libbeat.output.events.total"])
}

func TestCollectReceiverPipelineMetrics_PerContainerAggregation(t *testing.T) {
	// Two per-container receivers for the same base component should be aggregated.
	const base = "filebeatreceiver/_agent-component/filestream-default"
	const r1 = base + "/container-hash-aaa"
	const r2 = base + "/container-hash-bbb"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(100), registryBridgeReceiverKey, r1)
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(50), registryBridgeReceiverKey, r2)
	appendGaugeIntWithAttrs(sm, "filebeat.harvester.running", int64(3), registryBridgeReceiverKey, r1)
	appendGaugeIntWithAttrs(sm, "filebeat.harvester.running", int64(2), registryBridgeReceiverKey, r2)

	result := collectReceiverMetrics(md)
	// Only one base component entry
	require.Len(t, result, 1)
	fields, ok := result["filestream-default"]
	require.True(t, ok)
	// Values from both containers are summed
	assert.Equal(t, int64(150), fields["beat.stats.libbeat.output.events.acked"])
	assert.Equal(t, int64(5), fields["beat.stats.filebeat.harvester.running"])
}
