// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Reproduces elastic/elastic-agent#18047: a reader configured for delta
// temporality gets cumulative data for component-scoped metrics, because the
// per-component sub-provider aggregates with its own ManualReader, whose
// default temporality is cumulative, and Produce output is appended to the
// reader's result without re-aggregation.
func TestReaderTemporalityAppliesToComponentMetrics(t *testing.T) {
	ctx := context.Background()

	lp := newLifecycleMeterProvider(nil)
	delta := func(sdkmetric.InstrumentKind) metricdata.Temporality {
		return metricdata.DeltaTemporality
	}
	deltaReader := sdkmetric.NewManualReader(
		sdkmetric.WithProducer(lp.NewProducer(delta, nil)),
		sdkmetric.WithTemporalitySelector(delta),
	)
	// A second consumer with default (cumulative) temporality: each reader must
	// see component metrics aggregated its own way, from the same instruments.
	cumulativeReader := sdkmetric.NewManualReader(
		sdkmetric.WithProducer(lp.NewProducer(nil, nil)),
	)
	base := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(deltaReader),
		sdkmetric.WithReader(cumulativeReader),
	)
	t.Cleanup(func() { _ = base.Shutdown(ctx) })
	lp.setBase(base)

	record := func(mp metric.MeterProvider, scope string, opts ...metric.MeterOption) {
		t.Helper()
		c, err := mp.Meter(scope, opts...).Int64Counter("requests")
		if err != nil {
			t.Fatalf("counter on %s: %v", scope, err)
		}
		c.Add(ctx, 1)
	}

	record(lp, "service.scope")
	record(lp, "component.scope", metric.WithInstrumentationAttributes(
		attribute.String(otelComponentIDKey, "receiver/a"),
	))
	// What the gate-off path does: component scopes go straight to the base
	// provider, with no per-component sub-provider in between.
	record(base, "component.scope.ungated", metric.WithInstrumentationAttributes(
		attribute.String(otelComponentIDKey, "receiver/b"),
	))

	collect := func(r *sdkmetric.ManualReader) map[string]metricdata.Temporality {
		t.Helper()
		var rm metricdata.ResourceMetrics
		if err := r.Collect(ctx, &rm); err != nil {
			t.Fatalf("collect: %v", err)
		}
		got := map[string]metricdata.Temporality{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if sum, ok := m.Data.(metricdata.Sum[int64]); ok {
					got[sm.Scope.Name] = sum.Temporality
				}
			}
		}
		return got
	}

	scopes := []string{"service.scope", "component.scope.ungated", "component.scope"}

	gotDelta := collect(deltaReader)
	t.Logf("delta reader temporalities: %v", gotDelta)
	for _, scope := range scopes {
		if gotDelta[scope] != metricdata.DeltaTemporality {
			t.Errorf("delta reader, scope %q: got %v, want DeltaTemporality", scope, gotDelta[scope])
		}
	}

	gotCumulative := collect(cumulativeReader)
	t.Logf("cumulative reader temporalities: %v", gotCumulative)
	for _, scope := range scopes {
		if gotCumulative[scope] != metricdata.CumulativeTemporality {
			t.Errorf("cumulative reader, scope %q: got %v, want CumulativeTemporality", scope, gotCumulative[scope])
		}
	}
}
