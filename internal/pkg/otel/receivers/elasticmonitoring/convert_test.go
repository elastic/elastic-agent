// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func esExporterScope(exporterID string) instrumentation.Scope {
	return instrumentation.Scope{
		Name: "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter",
		Attributes: attribute.NewSet(
			attribute.String("otelcol.component.kind", "exporter"),
			attribute.String("otelcol.component.id", exporterID),
		),
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
		docsProcessed = int64(7)
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
		},
	}
	result := convertScopeMetrics([]metricdata.ScopeMetrics{scopeMetrics})
	assert.Equal(t, 1, len(result), "The scope metrics contain one exporter")

	metrics, ok := result[exporterID]
	require.Truef(t, ok, "Exporter metrics should contain metrics for the id '%v'", exporterID)

	beatEvent := mapstr.M{}
	addMetricsToEventFields(metrics, &beatEvent)

	maxEvents, err := beatEvent.GetValue(beatsQueueMaxEventsKey)
	assert.NoError(t, err)
	assert.Equal(t, queueCapacity, maxEvents)

	filledEvents, err := beatEvent.GetValue(beatsQueueFilledEventsKey)
	assert.NoError(t, err)
	assert.Equal(t, queueSize, filledEvents)

	filledPct, err := beatEvent.GetValue(beatsQueueFilledPctKey)
	assert.NoError(t, err)
	assert.Equal(t, float64(queueSize)/float64(queueCapacity), filledPct)

	eventsAcked, err := beatEvent.GetValue(beatsOutputEventsAckedKey)
	assert.NoError(t, err)
	assert.Equal(t, sentLogs+sentSpans+sentMetrics, eventsAcked)

	// Subtlety: what beats calls "dropped", OTel calls "failed."
	eventsDropped, err := beatEvent.GetValue(beatsOutputEventsDroppedKey)
	assert.NoError(t, err)
	assert.Equal(t, failedLogs+failedSpans+failedMetrics, eventsDropped)

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
}
