// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

func esExporterScope(exporterID string) instrumentation.Scope {
	return instrumentation.Scope{
		Name: "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter",
		Attributes: attribute.NewSet(
			attribute.String(otelComponentKindKey, "exporter"),
			attribute.String(otelComponentIDKey, exporterID),
		),
	}
}

func receiverScope(receiverID string) instrumentation.Scope {
	return instrumentation.Scope{
		Name: "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver",
		Attributes: attribute.NewSet(
			attribute.String(otelComponentKindKey, "receiver"),
			attribute.String(otelComponentIDKey, receiverID),
		),
	}
}

func gaugeMetricWithAttrs[N int64 | float64](name string, value N, attrs ...attribute.KeyValue) metricdata.Metrics {
	return metricdata.Metrics{
		Name: name,
		Data: metricdata.Gauge[N]{
			DataPoints: []metricdata.DataPoint[N]{
				{Value: value, Attributes: attribute.NewSet(attrs...)},
			},
		},
	}
}

func sumMetricWithAttrs[N int64 | float64](name string, value N, attrs ...attribute.KeyValue) metricdata.Metrics {
	return metricdata.Metrics{
		Name: name,
		Data: metricdata.Sum[N]{
			DataPoints: []metricdata.DataPoint[N]{
				{Value: value, Attributes: attribute.NewSet(attrs...)},
			},
		},
	}
}

func gaugeMetric[N int64 | float64](name string, value N) metricdata.Metrics {
	return metricdata.Metrics{
		Name: name,
		Data: metricdata.Gauge[N]{
			DataPoints: []metricdata.DataPoint[N]{
				{Value: value},
			},
		},
	}
}

func sumMetric[N int64 | float64](name string, values ...N) metricdata.Metrics {
	var dataPoints []metricdata.DataPoint[N]
	for _, v := range values {
		dataPoints = append(dataPoints, metricdata.DataPoint[N]{Value: v})
	}
	return metricdata.Metrics{
		Name: name,
		Data: metricdata.Sum[N]{DataPoints: dataPoints},
	}
}

func TestConvertAllMetrics(t *testing.T) {
	const exporterID = "elasticsearch/_agent-component/monitoring"
	// Test values here are mostly arbitrary except that no two are the same.
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
	scopeMetrics := metricdata.ScopeMetrics{
		Scope: esExporterScope(exporterID),
		Metrics: []metricdata.Metrics{
			gaugeMetric(otelQueueCapacityKey, queueCapacity),
			gaugeMetric(otelQueueSizeKey, queueSize),
			sumMetric(otelSentLogsKey, sentLogs),
			sumMetric(otelSentSpansKey, sentSpans),
			sumMetric(otelSentMetricsKey, sentMetrics),
			sumMetric(otelFailedLogsKey, failedLogs),
			sumMetric(otelFailedSpansKey, failedSpans),
			sumMetric(otelFailedMetricsKey, failedMetrics),
			sumMetric(otelDocsProcessedKey, docsProcessed),
			sumMetric(otelDocsRetriedKey, docsRetried),
			sumMetric(otelFlushedBytesKey, flushedBytes),
			sumMetric(otelBulkRequestsKey, bulkRequests),
		},
	}
	result := convertScopeMetrics([]metricdata.ScopeMetrics{scopeMetrics})
	assert.Equal(t, 1, len(result), "The scope metrics contain one exporter")

	metrics, ok := result[exporterID]
	require.Truef(t, ok, "Exporter metrics should contain metrics for the id '%v'", exporterID)

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

	// Subtlety: what beats calls "dropped", OTel calls "failed."
	expectedFailed := failedLogs + failedSpans + failedMetrics
	eventsDropped, err := beatEvent.GetValue(beatsOutputEventsDroppedKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedFailed, eventsDropped)

	eventsTotal, err := beatEvent.GetValue(beatsOutputEventsTotalKey)
	assert.NoError(t, err)
	assert.Equal(t, eventsTotal, docsProcessed)

	// Subtlety: what beats calls "failed", OTel calls "retried."
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

	// The ES exporter doesn't have a concept of batches that is semantically
	// identical to Beats, but bulk requests are a close analogue.
	batches, err := beatEvent.GetValue(beatsOutputEventsBatchesKey)
	assert.NoError(t, err)
	assert.Equal(t, bulkRequests, batches)
}

func TestCollectComponentInputMetrics_Basic(t *testing.T) {
	sm := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("beat.input.events.published", int64(42),
				attribute.String(otelInputIDKey, "logs.my-input"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm})
	require.Len(t, result, 1)
	comp, ok := result["filebeat-default"]
	require.True(t, ok)
	entry, ok := comp["logs_my-input"]
	require.True(t, ok)
	assert.Equal(t, "logs.my-input", entry["id"])
	assert.Equal(t, int64(42), entry["beat.input.events.published"])
}

func TestCollectComponentInputMetrics_WithInputType(t *testing.T) {
	sm := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("beat.input.events.published", int64(10),
				attribute.String(otelInputIDKey, "my-input"),
				attribute.String(otelInputTypeKey, "log"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm})
	require.Len(t, result, 1)
	comp := result["filebeat-default"]
	entry := comp["my-input"]
	assert.Equal(t, "log", entry["input"])
}

func TestCollectComponentInputMetrics_DotSanitization(t *testing.T) {
	sm := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("some.metric", int64(1),
				attribute.String(otelInputIDKey, "logs.my-input"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm})
	require.Len(t, result, 1)
	comp := result["filebeat-default"]
	_, hasUnderscore := comp["logs_my-input"]
	assert.True(t, hasUnderscore, "sanitized key should use underscores")
	_, hasDot := comp["logs.my-input"]
	assert.False(t, hasDot, "original dot-key should not be present")
	assert.Equal(t, "logs.my-input", comp["logs_my-input"]["id"])
}

func TestCollectComponentInputMetrics_NoInputID(t *testing.T) {
	sm := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetric("beat.input.events.published", int64(5)),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm})
	// Component is created but dataset should be empty (no input_id on data points)
	if comp, ok := result["filebeat-default"]; ok {
		assert.Empty(t, comp)
	}
}

func TestCollectComponentInputMetrics_MultipleInputsSameComponent(t *testing.T) {
	sm := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			sumMetricWithAttrs("beat.input.events.published", int64(7),
				attribute.String(otelInputIDKey, "input-a"),
			),
			sumMetricWithAttrs("beat.input.events.published", int64(3),
				attribute.String(otelInputIDKey, "input-b"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm})
	require.Len(t, result, 1)
	comp := result["filebeat-default"]
	require.Len(t, comp, 2)
	assert.Equal(t, "input-a", comp["input-a"]["id"])
	assert.Equal(t, "input-b", comp["input-b"]["id"])
	assert.Equal(t, int64(7), comp["input-a"]["beat.input.events.published"])
	assert.Equal(t, int64(3), comp["input-b"]["beat.input.events.published"])
}

func TestCollectComponentInputMetrics_AcrossScopes(t *testing.T) {
	sm1 := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("metric.one", int64(11),
				attribute.String(otelInputIDKey, "shared-input"),
			),
		},
	}
	sm2 := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("metric.two", int64(22),
				attribute.String(otelInputIDKey, "shared-input"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm1, sm2})
	require.Len(t, result, 1)
	comp := result["filebeat-default"]
	entry := comp["shared-input"]
	assert.Equal(t, int64(11), entry["metric.one"])
	assert.Equal(t, int64(22), entry["metric.two"])
}

func TestCollectComponentInputMetrics_DifferentComponents(t *testing.T) {
	sm1 := metricdata.ScopeMetrics{
		Scope: receiverScope("filebeatreceiver/_agent-component/filebeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("beat.input.events.published", int64(10),
				attribute.String(otelInputIDKey, "input-fb"),
			),
		},
	}
	sm2 := metricdata.ScopeMetrics{
		Scope: receiverScope("metricbeatreceiver/_agent-component/metricbeat-default"),
		Metrics: []metricdata.Metrics{
			gaugeMetricWithAttrs("beat.input.events.published", int64(20),
				attribute.String(otelInputIDKey, "input-mb"),
			),
		},
	}
	result := collectComponentInputMetrics([]metricdata.ScopeMetrics{sm1, sm2})
	require.Len(t, result, 2)
	fbComp := result["filebeat-default"]
	require.Len(t, fbComp, 1)
	assert.Equal(t, int64(10), fbComp["input-fb"]["beat.input.events.published"])

	mbComp := result["metricbeat-default"]
	require.Len(t, mbComp, 1)
	assert.Equal(t, int64(20), mbComp["input-mb"]["beat.input.events.published"])
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
