// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// metricdataToPdata converts an OTel SDK ResourceMetrics (from the internal
// telemetry ManualReader) into a pdata.Metrics, preserving scope names, scope
// attributes, metric names/units, and all data point values and attributes.
// Resource attributes are not currently emitted by the internal telemetry
// reader so they are not copied.
func metricdataToPdata(rm *metricdata.ResourceMetrics) pmetric.Metrics {
	md := pmetric.NewMetrics()
	pRM := md.ResourceMetrics().AppendEmpty()

	for _, sm := range rm.ScopeMetrics {
		pSM := pRM.ScopeMetrics().AppendEmpty()
		pSM.Scope().SetName(sm.Scope.Name)
		pSM.Scope().SetVersion(sm.Scope.Version)

		iter := sm.Scope.Attributes.Iter()
		for iter.Next() {
			kv := iter.Attribute()
			setAttrValue(pSM.Scope().Attributes(), string(kv.Key), kv.Value)
		}

		for _, m := range sm.Metrics {
			pM := pSM.Metrics().AppendEmpty()
			pM.SetName(m.Name)
			pM.SetDescription(m.Description)
			pM.SetUnit(m.Unit)
			convertMetricData(pM, m.Data)
		}
	}
	return md
}

func convertMetricData(pM pmetric.Metric, data metricdata.Aggregation) {
	switch v := data.(type) {
	case metricdata.Gauge[int64]:
		g := pM.SetEmptyGauge()
		for _, dp := range v.DataPoints {
			appendIntDataPoint(g.DataPoints().AppendEmpty(), dp)
		}
	case metricdata.Gauge[float64]:
		g := pM.SetEmptyGauge()
		for _, dp := range v.DataPoints {
			appendFloatDataPoint(g.DataPoints().AppendEmpty(), dp)
		}
	case metricdata.Sum[int64]:
		s := pM.SetEmptySum()
		s.SetIsMonotonic(v.IsMonotonic)
		s.SetAggregationTemporality(convertTemporality(v.Temporality))
		for _, dp := range v.DataPoints {
			appendIntDataPoint(s.DataPoints().AppendEmpty(), dp)
		}
	case metricdata.Sum[float64]:
		s := pM.SetEmptySum()
		s.SetIsMonotonic(v.IsMonotonic)
		s.SetAggregationTemporality(convertTemporality(v.Temporality))
		for _, dp := range v.DataPoints {
			appendFloatDataPoint(s.DataPoints().AppendEmpty(), dp)
		}
	}
}

func appendIntDataPoint(pDP pmetric.NumberDataPoint, dp metricdata.DataPoint[int64]) {
	pDP.SetIntValue(dp.Value)
	pDP.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
	pDP.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
	iter := dp.Attributes.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		setAttrValue(pDP.Attributes(), string(kv.Key), kv.Value)
	}
}

func appendFloatDataPoint(pDP pmetric.NumberDataPoint, dp metricdata.DataPoint[float64]) {
	pDP.SetDoubleValue(dp.Value)
	pDP.SetStartTimestamp(pcommon.NewTimestampFromTime(dp.StartTime))
	pDP.SetTimestamp(pcommon.NewTimestampFromTime(dp.Time))
	iter := dp.Attributes.Iter()
	for iter.Next() {
		kv := iter.Attribute()
		setAttrValue(pDP.Attributes(), string(kv.Key), kv.Value)
	}
}

func setAttrValue(attrs pcommon.Map, key string, val attribute.Value) {
	switch val.Type() {
	case attribute.STRING:
		attrs.PutStr(key, val.AsString())
	case attribute.INT64:
		attrs.PutInt(key, val.AsInt64())
	case attribute.FLOAT64:
		attrs.PutDouble(key, val.AsFloat64())
	case attribute.BOOL:
		attrs.PutBool(key, val.AsBool())
	}
}

func convertTemporality(t metricdata.Temporality) pmetric.AggregationTemporality {
	switch t {
	case metricdata.CumulativeTemporality:
		return pmetric.AggregationTemporalityCumulative
	case metricdata.DeltaTemporality:
		return pmetric.AggregationTemporalityDelta
	}
	return pmetric.AggregationTemporalityUnspecified
}
