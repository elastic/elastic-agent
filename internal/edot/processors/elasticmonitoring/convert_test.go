// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringprocessor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

const (
	fbreceiverScopeName = "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	mbreceiverScopeName = "github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"
)

// newMetricsWithScope returns a Metrics with one ResourceMetrics and one ScopeMetrics
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

// findMetric returns the metric with the given name in the output
// ResourceMetrics at index idx, failing the test if absent.
func findMetric(t *testing.T, out pmetric.Metrics, idx int, name string) pmetric.Metric {
	t.Helper()
	rm := out.ResourceMetrics().At(idx)
	for i := 0; i < rm.ScopeMetrics().Len(); i++ {
		sm := rm.ScopeMetrics().At(i)
		for j := 0; j < sm.Metrics().Len(); j++ {
			if sm.Metrics().At(j).Name() == name {
				return sm.Metrics().At(j)
			}
		}
	}
	t.Fatalf("metric %q not found in ResourceMetrics[%d]", name, idx)
	return pmetric.Metric{}
}

// hasMetric reports whether the output ResourceMetrics at index idx contains a
// metric with the given name.
func hasMetric(out pmetric.Metrics, idx int, name string) bool {
	rm := out.ResourceMetrics().At(idx)
	for i := 0; i < rm.ScopeMetrics().Len(); i++ {
		sm := rm.ScopeMetrics().At(i)
		for j := 0; j < sm.Metrics().Len(); j++ {
			if sm.Metrics().At(j).Name() == name {
				return true
			}
		}
	}
	return false
}

// findEvent returns the index of the first ResourceMetrics whose component.id
// (and, when inputID is non-empty, input.id) scope attributes match, or -1.
func findEvent(out pmetric.Metrics, compID, inputID string) int {
	for i := 0; i < out.ResourceMetrics().Len(); i++ {
		rm := out.ResourceMetrics().At(i)
		if rm.ScopeMetrics().Len() == 0 {
			continue
		}
		attrs := rm.ScopeMetrics().At(0).Scope().Attributes()
		if v, ok := attrs.Get(internaltelemetry.ComponentIDAttr); !ok || v.Str() != compID {
			continue
		}
		if inputID != "" {
			if v, ok := attrs.Get(internaltelemetry.InputIDAttr); !ok || v.Str() != inputID {
				continue
			}
		}
		return i
	}
	return -1
}

// findMetricTimestamp returns the Timestamp of the first data point of the named
// metric in the output ResourceMetrics at index idx.
func findMetricTimestamp(t *testing.T, out pmetric.Metrics, idx int, name string) pcommon.Timestamp {
	t.Helper()
	dps := numberDataPoints(findMetric(t, out, idx, name))
	require.Positive(t, dps.Len())
	return dps.At(0).Timestamp()
}

// findMetricValue searches for a metric by name in the output ResourceMetrics at index idx
// and returns its first data point value.
func findMetricValue(t *testing.T, out pmetric.Metrics, idx int, name string) any {
	t.Helper()
	dps := numberDataPoints(findMetric(t, out, idx, name))
	require.Positive(t, dps.Len())
	dp := dps.At(0)
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return dp.IntValue()
	case pmetric.NumberDataPointValueTypeDouble:
		return dp.DoubleValue()
	}
	return nil
}

func TestBuildExporterMetrics(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 100)

	cfg := &Config{ExporterNames: map[string]string{exporterID: "monitoring"}}
	out := pmetric.NewMetrics()
	buildExporterMetrics(zap.NewNop(), cfg, pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	compID, ok := out.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr)
	require.True(t, ok)
	assert.Equal(t, "monitoring", compID.Str())
	assert.Equal(t, int64(100), findMetricValue(t, out, 0, beatsQueueMaxEventsKey))
}

func TestBuildProcessedMetrics_ServiceResourcePropagated(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 1)

	res := pcommon.NewResource()
	res.Attributes().PutStr("service.name", "elastic-otel-collector")
	res.Attributes().PutStr("service.version", "9.6.0")

	cfg := &Config{ExporterNames: map[string]string{exporterID: "monitoring"}}
	out := buildProcessedMetrics(zap.NewNop(), cfg, res, md)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	resAttrs := out.ResourceMetrics().At(0).Resource().Attributes()
	svcName, ok := resAttrs.Get("service.name")
	require.True(t, ok, "service.name resource attribute must be propagated")
	assert.Equal(t, "elastic-otel-collector", svcName.Str())
	svcVer, ok := resAttrs.Get("service.version")
	require.True(t, ok, "service.version resource attribute must be propagated")
	assert.Equal(t, "9.6.0", svcVer.Str())
}

func TestBuildExporterMetrics_UnknownExporterFallsBackToExporterID(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	appendGaugeInt(sm, otelQueueCapacityKey, 1)

	out := pmetric.NewMetrics()
	buildExporterMetrics(zap.NewNop(), &Config{}, pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	compID, ok := out.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr)
	require.True(t, ok)
	assert.Equal(t, exporterID, compID.Str())
}

func TestBuildInputMetrics(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", 42, otelInputIDKey, "logs.my-input")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	scopeAttrs := out.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes()
	compID, _ := scopeAttrs.Get(internaltelemetry.ComponentIDAttr)
	assert.Equal(t, "filebeat-default", compID.Str())
	inputID, _ := scopeAttrs.Get(internaltelemetry.InputIDAttr)
	assert.Equal(t, "logs.my-input", inputID.Str())
	assert.Equal(t, int64(42), findMetricValue(t, out, 0, "filebeat_input.beat.input.events.published"))
}

func TestBuildInputMetrics_IgnoresNonFilebeatComponents(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(mbreceiverScopeName, "metricbeatreceiver/_agent-component/metricbeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", 1, otelInputIDKey, "some-input")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	assert.Equal(t, 0, out.ResourceMetrics().Len())
}

func TestBuildReceiverPipelineMetrics(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", 7, registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	compID, _ := out.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr)
	assert.Equal(t, "filestream-default", compID.Str())
	assert.Equal(t, int64(7), findMetricValue(t, out, 0, "beat.stats.libbeat.output.events.acked"))
}

func TestBuildExporterMetrics_TimestampPropagated(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	md, sm := newMetricsWithExporterScope(exporterID)
	const wantTS = pcommon.Timestamp(1_000_000_000)
	m := sm.Metrics().AppendEmpty()
	m.SetName(otelQueueCapacityKey)
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(100)
	dp.SetTimestamp(wantTS)

	cfg := &Config{ExporterNames: map[string]string{exporterID: "monitoring"}}
	out := pmetric.NewMetrics()
	buildExporterMetrics(zap.NewNop(), cfg, pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, wantTS, findMetricTimestamp(t, out, 0, beatsQueueMaxEventsKey))
}

func TestBuildInputMetrics_TimestampPropagated(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	const wantTS = pcommon.Timestamp(2_000_000_000)
	m := sm.Metrics().AppendEmpty()
	m.SetName("beat.input.events.published")
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetIntValue(7)
	dp.SetTimestamp(wantTS)
	dp.Attributes().PutStr(otelInputIDKey, "logs.my-input")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, wantTS, findMetricTimestamp(t, out, 0, "filebeat_input.beat.input.events.published"))
}

func TestBuildReceiverPipelineMetrics_TimestampPropagated(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	const wantTS = pcommon.Timestamp(3_000_000_000)
	m := sm.Metrics().AppendEmpty()
	m.SetName("libbeat.output.events.acked")
	dp := m.SetEmptySum().DataPoints().AppendEmpty()
	dp.SetIntValue(42)
	dp.SetTimestamp(wantTS)
	dp.Attributes().PutStr(registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, wantTS, findMetricTimestamp(t, out, 0, "beat.stats.libbeat.output.events.acked"))
}

func TestBuildReceiverPipelineMetrics_NoData(t *testing.T) {
	md, _ := newMetricsWithScope("some.unrelated.scope")

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	assert.Equal(t, 0, out.ResourceMetrics().Len())
}

func TestConvertAllExporterMetrics(t *testing.T) {
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

	cfg := &Config{ExporterNames: map[string]string{exporterID: "monitoring"}}
	out := pmetric.NewMetrics()
	buildExporterMetrics(zap.NewNop(), cfg, pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())

	assert.Equal(t, queueCapacity, findMetricValue(t, out, 0, beatsQueueMaxEventsKey))
	assert.Equal(t, queueSize, findMetricValue(t, out, 0, beatsQueueFilledEventsKey))
	assert.Equal(t, float64(queueSize)/float64(queueCapacity), findMetricValue(t, out, 0, beatsQueueFilledPctKey))

	expectedSent := sentLogs + sentSpans + sentMetrics
	assert.Equal(t, expectedSent, findMetricValue(t, out, 0, beatsOutputEventsAckedKey))

	expectedFailed := failedLogs + failedSpans + failedMetrics
	assert.Equal(t, expectedFailed, findMetricValue(t, out, 0, beatsOutputEventsDroppedKey))

	assert.Equal(t, docsProcessed, findMetricValue(t, out, 0, beatsOutputEventsTotalKey))
	assert.Equal(t, docsRetried, findMetricValue(t, out, 0, beatsOutputEventsFailedKey))
	assert.Equal(t, flushedBytes, findMetricValue(t, out, 0, beatsOutputWriteBytesKey))
	assert.Equal(t, docsProcessed-expectedSent-expectedFailed, findMetricValue(t, out, 0, beatsOutputEventsActiveKey))
	assert.Equal(t, bulkRequests, findMetricValue(t, out, 0, beatsOutputEventsBatchesKey))
}

func TestBuildInputMetrics_InputTypeAttribute(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm, "beat.input.events.published", int64(10),
		otelInputIDKey, "my-input", otelInputTypeKey, "log")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	inputType, ok := out.ResourceMetrics().At(0).ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.InputTypeAttr)
	require.True(t, ok)
	assert.Equal(t, "log", inputType.Str())
}

func TestBuildInputMetrics_NoInputID(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeInt(sm, "beat.input.events.published", int64(5))

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	assert.Equal(t, 0, out.ResourceMetrics().Len())
}

func TestBuildInputMetrics_MultipleInputsSameComponent(t *testing.T) {
	md, sm := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendSumIntWithAttrs(sm, "beat.input.events.published", int64(7), otelInputIDKey, "input-a")
	appendSumIntWithAttrs(sm, "beat.input.events.published", int64(3), otelInputIDKey, "input-b")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 2, out.ResourceMetrics().Len())
	idxA := findEvent(out, "filebeat-default", "input-a")
	require.NotEqual(t, -1, idxA)
	assert.Equal(t, int64(7), findMetricValue(t, out, idxA, "filebeat_input.beat.input.events.published"))
	idxB := findEvent(out, "filebeat-default", "input-b")
	require.NotEqual(t, -1, idxB)
	assert.Equal(t, int64(3), findMetricValue(t, out, idxB, "filebeat_input.beat.input.events.published"))
}

func TestBuildInputMetrics_AcrossScopes(t *testing.T) {
	md, sm1 := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm1, "metric.one", int64(11), otelInputIDKey, "shared-input")

	sm2 := appendScopeToMetrics(md, fbreceiverScopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, "filebeatreceiver/_agent-component/filebeat-default",
	)
	appendGaugeIntWithAttrs(sm2, "metric.two", int64(22), otelInputIDKey, "shared-input")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len(), "metrics for the same input across scopes must merge into one event")
	assert.Equal(t, int64(11), findMetricValue(t, out, 0, "filebeat_input.metric.one"))
	assert.Equal(t, int64(22), findMetricValue(t, out, 0, "filebeat_input.metric.two"))
}

func TestBuildInputMetrics_DifferentComponents(t *testing.T) {
	md, sm1 := newMetricsWithReceiverScope(fbreceiverScopeName, "filebeatreceiver/_agent-component/filebeat-default")
	appendGaugeIntWithAttrs(sm1, "beat.input.events.published", int64(10), otelInputIDKey, "input-a")

	sm2 := appendScopeToMetrics(md, fbreceiverScopeName,
		otelComponentKindKey, "receiver",
		otelComponentIDKey, "filebeatreceiver/_agent-component/filebeat-monitoring",
	)
	appendGaugeIntWithAttrs(sm2, "beat.input.events.published", int64(20), otelInputIDKey, "input-b")

	out := pmetric.NewMetrics()
	buildInputMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 2, out.ResourceMetrics().Len())
	idxDefault := findEvent(out, "filebeat-default", "input-a")
	require.NotEqual(t, -1, idxDefault)
	assert.Equal(t, int64(10), findMetricValue(t, out, idxDefault, "filebeat_input.beat.input.events.published"))
	idxMonitoring := findEvent(out, "filebeat-monitoring", "input-b")
	require.NotEqual(t, -1, idxMonitoring)
	assert.Equal(t, int64(20), findMetricValue(t, out, idxMonitoring, "filebeat_input.beat.input.events.published"))
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

func TestBuildReceiverPipelineMetrics_BeatTypePrefix(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(3), registryBridgeReceiverKey, receiverID)
	appendSumIntWithAttrs(sm, "pipeline.events.published", int64(42), registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, int64(3), findMetricValue(t, out, 0, "beat.stats.filebeat.pipeline.clients"))
	assert.Equal(t, int64(42), findMetricValue(t, out, 0, "beat.stats.filebeat.pipeline.events.published"))
}

func TestBuildReceiverPipelineMetrics_FloatGauge(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeFloat64WithAttrs(sm, "pipeline.queue.filled.pct", float64(0.42), registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, float64(0.42), findMetricValue(t, out, 0, "beat.stats.filebeat.pipeline.queue.filled.pct"))
}

func TestBuildReceiverPipelineMetrics_AllMetricsCollected(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filebeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "output.events.active", int64(5), registryBridgeReceiverKey, receiverID)
	appendGaugeIntWithAttrs(sm, "harvester.running", int64(3), registryBridgeReceiverKey, receiverID)
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(2), registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, int64(2), findMetricValue(t, out, 0, "beat.stats.filebeat.pipeline.clients"))
	assert.Equal(t, int64(5), findMetricValue(t, out, 0, "beat.stats.filebeat.output.events.active"))
	assert.Equal(t, int64(3), findMetricValue(t, out, 0, "beat.stats.filebeat.harvester.running"))
}

func TestBuildReceiverPipelineMetrics_WrongScopeSkipped(t *testing.T) {
	md, sm := newMetricsWithExporterScope("elasticsearch/_agent-component/monitoring")
	appendGaugeInt(sm, "pipeline.clients", int64(1))

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	assert.Equal(t, 0, out.ResourceMetrics().Len())
}

func TestBuildReceiverPipelineMetrics_NoReceiverAttr(t *testing.T) {
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeInt(sm, "pipeline.clients", int64(1))

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	assert.Equal(t, 0, out.ResourceMetrics().Len())
}

func TestBuildReceiverPipelineMetrics_MultipleReceivers(t *testing.T) {
	const fbReceiverID = "filebeatreceiver/_agent-component/filebeat-default"
	const mbReceiverID = "metricbeatreceiver/_agent-component/metricbeat-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(2), registryBridgeReceiverKey, fbReceiverID)
	appendGaugeIntWithAttrs(sm, "pipeline.clients", int64(5), registryBridgeReceiverKey, mbReceiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 2, out.ResourceMetrics().Len())
	fbIdx := findEvent(out, "filebeat-default", "")
	require.NotEqual(t, -1, fbIdx)
	assert.Equal(t, int64(2), findMetricValue(t, out, fbIdx, "beat.stats.filebeat.pipeline.clients"))
	mbIdx := findEvent(out, "metricbeat-default", "")
	require.NotEqual(t, -1, mbIdx)
	assert.Equal(t, int64(5), findMetricValue(t, out, mbIdx, "beat.stats.metricbeat.pipeline.clients"))
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

func TestBuildReceiverPipelineMetrics_LibbeatPrefix(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.total", int64(200), registryBridgeReceiverKey, receiverID)
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(180), registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	assert.Equal(t, int64(200), findMetricValue(t, out, 0, "beat.stats.libbeat.output.events.total"))
	assert.Equal(t, int64(180), findMetricValue(t, out, 0, "beat.stats.libbeat.output.events.acked"))
	assert.False(t, hasMetric(out, 0, "beat.stats.filebeat.libbeat.output.events.total"),
		"libbeat.* metric must not get the beat-type prefix")
}

func TestBuildReceiverPipelineMetrics_PerContainerAggregation(t *testing.T) {
	const base = "filebeatreceiver/_agent-component/filestream-default"
	const r1 = base + "/container-hash-aaa"
	const r2 = base + "/container-hash-bbb"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(100), registryBridgeReceiverKey, r1)
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(50), registryBridgeReceiverKey, r2)
	appendGaugeIntWithAttrs(sm, "filebeat.harvester.running", int64(3), registryBridgeReceiverKey, r1)
	appendGaugeIntWithAttrs(sm, "filebeat.harvester.running", int64(2), registryBridgeReceiverKey, r2)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	require.NotEqual(t, -1, findEvent(out, "filestream-default", ""))
	assert.Equal(t, int64(150), findMetricValue(t, out, 0, "beat.stats.libbeat.output.events.acked"))
	assert.Equal(t, int64(5), findMetricValue(t, out, 0, "beat.stats.filebeat.harvester.running"))
}

func TestBuildReceiverPipelineMetrics_MonitoringComponentPreservesFullID(t *testing.T) {
	const r1 = "metricbeatreceiver/_agent-component/http/metrics-monitoring/stream-aaa"
	const r2 = "metricbeatreceiver/_agent-component/beat/metrics-monitoring/stream-bbb"
	md, sm := newMetricsWithRegistryBridgeScope()
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(10), registryBridgeReceiverKey, r1)
	appendSumIntWithAttrs(sm, "libbeat.output.events.acked", int64(20), registryBridgeReceiverKey, r2)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 2, out.ResourceMetrics().Len())
	assert.NotEqual(t, -1, findEvent(out, "http/metrics-monitoring", ""))
	assert.NotEqual(t, -1, findEvent(out, "beat/metrics-monitoring", ""))
	assert.Equal(t, -1, findEvent(out, "http", ""), "comp.ID must not be cut at the wrong slash")
	assert.Equal(t, -1, findEvent(out, "beat", ""), "comp.ID must not be cut at the wrong slash")
}

// TestBuildReceiverPipelineMetrics_MetricTypeAndUnitPreserved verifies that the
// output mirrors the source metric's type, unit, temporality, and monotonicity
// rather than coercing everything to gauges.
func TestBuildReceiverPipelineMetrics_MetricTypeAndUnitPreserved(t *testing.T) {
	const receiverID = "filebeatreceiver/_agent-component/filestream-default"
	md, sm := newMetricsWithRegistryBridgeScope()
	m := sm.Metrics().AppendEmpty()
	m.SetName("libbeat.output.events.acked")
	m.SetUnit("{events}")
	s := m.SetEmptySum()
	s.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	s.SetIsMonotonic(true)
	dp := s.DataPoints().AppendEmpty()
	dp.SetIntValue(7)
	dp.Attributes().PutStr(registryBridgeReceiverKey, receiverID)

	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	require.Equal(t, 1, out.ResourceMetrics().Len())
	outMetric := findMetric(t, out, 0, "beat.stats.libbeat.output.events.acked")
	require.Equal(t, pmetric.MetricTypeSum, outMetric.Type())
	assert.Equal(t, "{events}", outMetric.Unit())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, outMetric.Sum().AggregationTemporality())
	assert.True(t, outMetric.Sum().IsMonotonic())
}
