// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestFormatOpenMetrics_CounterGaugeHistogram(t *testing.T) {
	start := time.Date(2026, 5, 20, 13, 34, 17, 338_924_467, time.UTC)
	now := time.Date(2026, 5, 20, 13, 36, 21, 402_700_069, time.UTC)

	sms := []metricdata.ScopeMetrics{{
		Scope: instrumentation.Scope{
			Name: "go.opentelemetry.io/collector/exporter/elasticsearchexporter",
			Attributes: attribute.NewSet(
				attribute.String("otelcol.component.id", "elasticsearch/log-mock-es"),
				attribute.String("otelcol.component.kind", "exporter"),
			),
		},
		Metrics: []metricdata.Metrics{
			{
				Name:        "otelcol_exporter_sent_log_records",
				Description: "Number of log records successfully sent.",
				Unit:        "{records}",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[int64]{{
						Attributes: attribute.NewSet(attribute.String("otelcol.component.outcome", "success")),
						StartTime:  start,
						Time:       now,
						Value:      126,
					}},
				},
			},
			{
				Name:        "otelcol_exporter_queue_size",
				Description: "Current queue depth.",
				Data: metricdata.Gauge[int64]{
					DataPoints: []metricdata.DataPoint[int64]{{
						Attributes: attribute.NewSet(),
						Time:       now,
						Value:      0,
					}},
				},
			},
			{
				Name:        "otelcol_exporter_send_failed_log_records",
				Description: "Failed log records.",
				Data: metricdata.Sum[float64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: true,
					DataPoints: []metricdata.DataPoint[float64]{{
						Attributes: attribute.NewSet(),
						StartTime:  start,
						Time:       now,
						Value:      0.5,
					}},
				},
			},
			{
				Name:        "otelcol_exporter_bulk_request_duration",
				Description: "Latency of bulk requests in seconds.",
				Unit:        "s",
				Data: metricdata.Histogram[float64]{
					Temporality: metricdata.CumulativeTemporality,
					DataPoints: []metricdata.HistogramDataPoint[float64]{{
						Attributes:   attribute.NewSet(),
						StartTime:    start,
						Time:         now,
						Bounds:       []float64{0.1, 0.5, 1.0},
						BucketCounts: []uint64{2, 3, 1, 0},
						Sum:          1.23,
						Count:        6,
					}},
				},
			},
			{
				Name:        "otelcol_exporter_in_flight_requests",
				Description: "Currently in-flight requests.",
				Data: metricdata.Sum[int64]{
					Temporality: metricdata.CumulativeTemporality,
					IsMonotonic: false,
					DataPoints: []metricdata.DataPoint[int64]{{
						Attributes: attribute.NewSet(),
						Time:       now,
						Value:      3,
					}},
				},
			},
		},
	}}

	got := formatOpenMetrics(sms)

	for _, want := range []string{
		"# HELP otelcol_exporter_sent_log_records Number of log records successfully sent.\n",
		"# UNIT otelcol_exporter_sent_log_records {records}\n",
		"# TYPE otelcol_exporter_sent_log_records counter\n",
		`otelcol_exporter_sent_log_records{otelcol_component_outcome="success",otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter"} 126 1779284181.403`,
		`otelcol_exporter_sent_log_records_created{otelcol_component_outcome="success",otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter"} 1779284057.339`,
		"# TYPE otelcol_exporter_queue_size gauge\n",
		"# TYPE otelcol_exporter_send_failed_log_records counter\n",
		"# TYPE otelcol_exporter_bulk_request_duration histogram\n",
		`otelcol_exporter_bulk_request_duration_bucket{otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter",le="0.1"} 2`,
		`otelcol_exporter_bulk_request_duration_bucket{otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter",le="+Inf"} 6`,
		`otelcol_exporter_bulk_request_duration_sum{otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter"} 1.23`,
		`otelcol_exporter_bulk_request_duration_count{otelcol_component_id="elasticsearch/log-mock-es",otelcol_component_kind="exporter"} 6`,
		// non-monotonic Sum collapses to gauge (OpenMetrics has no non-monotonic counter)
		"# TYPE otelcol_exporter_in_flight_requests gauge\n",
		"# EOF\n",
	} {
		assert.Contains(t, got, want, "expected output to contain %q", want)
	}

	// _created lines are only emitted for cumulative monotonic counters,
	// not for gauges or non-monotonic sums.
	assert.NotContains(t, got, "otelcol_exporter_queue_size_created", "gauges must not emit _created")
	assert.NotContains(t, got, "otelcol_exporter_in_flight_requests_created", "non-monotonic Sum must not emit _created")
}

func TestFormatOpenMetrics_DeltaTemporality(t *testing.T) {
	now := time.Date(2026, 5, 20, 13, 36, 21, 0, time.UTC)
	sms := []metricdata.ScopeMetrics{{
		Scope: instrumentation.Scope{Name: "test"},
		Metrics: []metricdata.Metrics{{
			Name: "my_counter",
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.DeltaTemporality,
				IsMonotonic: true,
				DataPoints: []metricdata.DataPoint[int64]{{
					Time:  now,
					Value: 42,
				}},
			},
		}},
	}}

	got := formatOpenMetrics(sms)
	assert.Contains(t, got, `my_counter{__temporality="delta"}`,
		"delta temporality must be preserved as a synthetic label")
	assert.NotContains(t, got, "my_counter_created",
		"_created is only meaningful for cumulative monotonic counters")
}

func TestFormatOpenMetrics_LabelSanitizationAndEscaping(t *testing.T) {
	sms := []metricdata.ScopeMetrics{{
		Scope: instrumentation.Scope{},
		Metrics: []metricdata.Metrics{{
			Name: "test_metric",
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{{
					Attributes: attribute.NewSet(
						attribute.String("dotted.label.name", `value with "quotes" and \backslash`),
						attribute.String("dashed-name", "normal"),
					),
					Value: 7,
				}},
			},
		}},
	}}

	got := formatOpenMetrics(sms)
	// dots and dashes become underscores in label names
	assert.Contains(t, got, "dotted_label_name=")
	assert.Contains(t, got, "dashed_name=")
	// quotes and backslashes in values are escaped
	assert.Contains(t, got, `dotted_label_name="value with \"quotes\" and \\backslash"`)
}

func TestFormatOpenMetrics_IsMuchSmallerThanJSONReflect(t *testing.T) {
	// Approximates the production cardinality that caused the original
	// 142KB log line: many receiver/exporter scopes, a handful of metrics
	// per scope, mostly one data point per metric.
	now := time.Now()
	start := now.Add(-time.Hour)
	mkAttrs := func(outcome string) attribute.Set {
		return attribute.NewSet(attribute.String("otelcol.component.outcome", outcome))
	}
	mkSumPoint := func(v int64) metricdata.DataPoint[int64] {
		return metricdata.DataPoint[int64]{
			Attributes: mkAttrs("success"),
			StartTime:  start,
			Time:       now,
			Value:      v,
		}
	}
	mkCounter := func(name, desc string, v int64) metricdata.Metrics {
		return metricdata.Metrics{
			Name:        name,
			Description: desc,
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints:  []metricdata.DataPoint[int64]{mkSumPoint(v)},
			},
		}
	}

	var sms []metricdata.ScopeMetrics
	for i := 0; i < 25; i++ {
		scopeID := "filebeatreceiver/_agent-component/log-mock-es-abc-def-stream-" + string(rune('a'+i%26))
		scope := instrumentation.Scope{
			Attributes: attribute.NewSet(
				attribute.String("otelcol.component.id", scopeID),
				attribute.String("otelcol.component.kind", "receiver"),
			),
		}
		sms = append(sms, metricdata.ScopeMetrics{
			Scope: scope,
			Metrics: []metricdata.Metrics{
				mkCounter("otelcol_exporter_sent_log_records", "Number of items passed to the exporter.", 100),
				mkCounter("otelcol_exporter_send_failed_log_records", "Number of failed items.", 0),
				mkCounter("otelcol_receiver_accepted_log_records", "Number of items received.", 100),
				mkCounter("otelcol_receiver_refused_log_records", "Number of items refused.", 0),
			},
		})
	}

	omText := formatOpenMetrics(sms)
	require.True(t, strings.HasSuffix(omText, "# EOF\n"))

	jsonBytes, err := json.Marshal(sms)
	require.NoError(t, err)
	t.Logf("openmetrics: %d bytes, json reflect: %d bytes (%.2fx smaller)",
		len(omText), len(jsonBytes), float64(len(jsonBytes))/float64(len(omText)))
	assert.Less(t, len(omText), len(jsonBytes),
		"OpenMetrics output should be smaller than JSON-reflected output for the same data")
}
