// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func makeResourceMetrics(scopes []metricdata.ScopeMetrics) *metricdata.ResourceMetrics {
	return &metricdata.ResourceMetrics{
		Resource:     resource.NewSchemaless(),
		ScopeMetrics: scopes,
	}
}

func scopeWithAttrs(name string, attrs ...attribute.KeyValue) instrumentation.Scope {
	return instrumentation.Scope{
		Name:       name,
		Attributes: attribute.NewSet(attrs...),
	}
}

func TestMetricdataToPdata_ScopeNameAndAttributes(t *testing.T) {
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("my/scope",
				attribute.String("otelcol.component.id", "elasticsearch/foo"),
				attribute.String("otelcol.component.kind", "exporter"),
			),
			Metrics: []metricdata.Metrics{},
		},
	})

	md := metricdataToPdata(rm)

	require.Equal(t, 1, md.ResourceMetrics().Len())
	sms := md.ResourceMetrics().At(0).ScopeMetrics()
	require.Equal(t, 1, sms.Len())

	sm := sms.At(0)
	assert.Equal(t, "my/scope", sm.Scope().Name())

	id, ok := sm.Scope().Attributes().Get("otelcol.component.id")
	require.True(t, ok)
	assert.Equal(t, "elasticsearch/foo", id.Str())

	kind, ok := sm.Scope().Attributes().Get("otelcol.component.kind")
	require.True(t, ok)
	assert.Equal(t, "exporter", kind.Str())
}

func TestMetricdataToPdata_Int64Gauge(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("test"),
			Metrics: []metricdata.Metrics{
				{
					Name: "otelcol_exporter_queue_size",
					Data: metricdata.Gauge[int64]{
						DataPoints: []metricdata.DataPoint[int64]{
							{
								Value:     42,
								StartTime: ts.Add(-time.Second),
								Time:      ts,
								Attributes: attribute.NewSet(
									attribute.String("exporter", "elasticsearch"),
								),
							},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	sm := md.ResourceMetrics().At(0).ScopeMetrics().At(0)
	require.Equal(t, 1, sm.Metrics().Len())
	m := sm.Metrics().At(0)
	assert.Equal(t, "otelcol_exporter_queue_size", m.Name())
	assert.Equal(t, pmetric.MetricTypeGauge, m.Type())

	dps := m.Gauge().DataPoints()
	require.Equal(t, 1, dps.Len())
	dp := dps.At(0)
	assert.Equal(t, pmetric.NumberDataPointValueTypeInt, dp.ValueType())
	assert.Equal(t, int64(42), dp.IntValue())

	v, ok := dp.Attributes().Get("exporter")
	require.True(t, ok)
	assert.Equal(t, "elasticsearch", v.Str())
}

func TestMetricdataToPdata_Float64Gauge(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("test"),
			Metrics: []metricdata.Metrics{
				{
					Name: "some.float.metric",
					Data: metricdata.Gauge[float64]{
						DataPoints: []metricdata.DataPoint[float64]{
							{Value: 3.14, Time: ts},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, pmetric.MetricTypeGauge, m.Type())
	dp := m.Gauge().DataPoints().At(0)
	assert.Equal(t, pmetric.NumberDataPointValueTypeDouble, dp.ValueType())
	assert.InDelta(t, 3.14, dp.DoubleValue(), 1e-9)
}

func TestMetricdataToPdata_Int64Sum(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("test"),
			Metrics: []metricdata.Metrics{
				{
					Name: "otelcol_exporter_sent_log_records",
					Data: metricdata.Sum[int64]{
						IsMonotonic: true,
						Temporality: metricdata.CumulativeTemporality,
						DataPoints: []metricdata.DataPoint[int64]{
							{Value: 100, Time: ts},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, pmetric.MetricTypeSum, m.Type())
	assert.True(t, m.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityCumulative, m.Sum().AggregationTemporality())
	assert.Equal(t, int64(100), m.Sum().DataPoints().At(0).IntValue())
}

func TestMetricdataToPdata_Float64Sum(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("test"),
			Metrics: []metricdata.Metrics{
				{
					Name: "some.float.sum",
					Data: metricdata.Sum[float64]{
						IsMonotonic: false,
						Temporality: metricdata.DeltaTemporality,
						DataPoints: []metricdata.DataPoint[float64]{
							{Value: 2.718, Time: ts},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, pmetric.MetricTypeSum, m.Type())
	assert.False(t, m.Sum().IsMonotonic())
	assert.Equal(t, pmetric.AggregationTemporalityDelta, m.Sum().AggregationTemporality())
	assert.InDelta(t, 2.718, m.Sum().DataPoints().At(0).DoubleValue(), 1e-9)
}

func TestMetricdataToPdata_DataPointAttributes(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("test"),
			Metrics: []metricdata.Metrics{
				{
					Name: "some.metric",
					Data: metricdata.Gauge[int64]{
						DataPoints: []metricdata.DataPoint[int64]{
							{
								Value: 7,
								Time:  ts,
								Attributes: attribute.NewSet(
									attribute.String("input_id", "my-input"),
									attribute.String("input_type", "log"),
									attribute.Int64("count", 99),
									attribute.Bool("active", true),
								),
							},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	dp := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)

	v, ok := dp.Attributes().Get("input_id")
	require.True(t, ok)
	assert.Equal(t, "my-input", v.Str())

	v, ok = dp.Attributes().Get("input_type")
	require.True(t, ok)
	assert.Equal(t, "log", v.Str())

	v, ok = dp.Attributes().Get("count")
	require.True(t, ok)
	assert.Equal(t, int64(99), v.Int())

	v, ok = dp.Attributes().Get("active")
	require.True(t, ok)
	assert.True(t, v.Bool())
}

func TestMetricdataToPdata_MultipleScopes(t *testing.T) {
	ts := time.Now()
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope:   scopeWithAttrs("scope-a"),
			Metrics: []metricdata.Metrics{{Name: "metric.a", Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{Value: 1, Time: ts}}}}},
		},
		{
			Scope:   scopeWithAttrs("scope-b"),
			Metrics: []metricdata.Metrics{{Name: "metric.b", Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{Value: 2, Time: ts}}}}},
		},
	})

	md := metricdataToPdata(rm)

	sms := md.ResourceMetrics().At(0).ScopeMetrics()
	require.Equal(t, 2, sms.Len())
	assert.Equal(t, "scope-a", sms.At(0).Scope().Name())
	assert.Equal(t, "scope-b", sms.At(1).Scope().Name())
	assert.Equal(t, "metric.a", sms.At(0).Metrics().At(0).Name())
	assert.Equal(t, "metric.b", sms.At(1).Metrics().At(0).Name())
}

func TestMetricdataToPdata_RegistryBridgeReceiverAttr(t *testing.T) {
	// Verify that the "receiver" data point attribute is preserved, since the
	// connector's collectReceiverMetrics depends on it.
	ts := time.Now()
	otelID := "filebeatreceiver/_agent-component/filebeat-0"
	rm := makeResourceMetrics([]metricdata.ScopeMetrics{
		{
			Scope: scopeWithAttrs("github.com/elastic/beats/v7/x-pack/otel/telemetry"),
			Metrics: []metricdata.Metrics{
				{
					Name: "harvester.running",
					Data: metricdata.Gauge[int64]{
						DataPoints: []metricdata.DataPoint[int64]{
							{
								Value: 5,
								Time:  ts,
								Attributes: attribute.NewSet(
									attribute.String("receiver", otelID),
								),
							},
						},
					},
				},
			},
		},
	})

	md := metricdataToPdata(rm)

	dp := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Gauge().DataPoints().At(0)
	v, ok := dp.Attributes().Get("receiver")
	require.True(t, ok)
	assert.Equal(t, otelID, v.Str())
}
