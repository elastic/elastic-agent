// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"context"
	"errors"
	"sync"

	"go.opentelemetry.io/collector/service/telemetry"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// otelComponentIDKey is the instrumentation *scope* attribute the collector
// injects per component instance when the telemetry.newPipelineTelemetry
// feature gate is on (see service/internal/componentattribute).
//
// The OTel SDK caches meters by {name, version, schemaURL, attributes}, and
// that cache is append-only: a meter is never released. With a component ID in
// the scope, every component instance the collector ever builds permanently
// retains its meters, instruments and aggregators. Under partial receiver
// reload — where the service, and so the MeterProvider, is never rebuilt —
// that grows without bound.
//
// lifecycleMeterProvider gives each component its own sdkmetric.MeterProvider
// so the whole lot can be dropped when the component stops. Scope attributes
// are forwarded untouched, so metric granularity is unchanged.
const otelComponentIDKey = "otelcol.component.id"

type lifecycleMeterProvider struct {
	embedded.MeterProvider

	// base serves scopes that carry no component ID (service-level telemetry).
	// It is set once, after construction, because the readers that feed it need
	// to reference this provider as their Producer.
	base  telemetry.MeterProvider
	views []sdkmetric.View

	mu    sync.Mutex
	specs []readerSpec
	subs  map[string]*componentMeters
}

// readerSpec records the temporality and aggregation selectors of one consumer
// of component-scoped metrics. Readers do not re-aggregate Producer output, so
// each consumer needs the data aggregated its own way; every sub-provider gets
// one dedicated pipeline per spec (elastic/elastic-agent#18047).
type readerSpec struct {
	temporality sdkmetric.TemporalitySelector
	aggregation sdkmetric.AggregationSelector
}

type componentMeters struct {
	mp *sdkmetric.MeterProvider
	// readers aggregate this component's metrics once per consumer registered
	// via NewProducer, in registration order, each with that consumer's
	// temporality and aggregation.
	readers []*sdkmetric.ManualReader
}

func newLifecycleMeterProvider(views []sdkmetric.View) *lifecycleMeterProvider {
	return &lifecycleMeterProvider{
		views: views,
		subs:  make(map[string]*componentMeters),
	}
}

func (l *lifecycleMeterProvider) setBase(base telemetry.MeterProvider) {
	l.base = base
}

// Meter routes to a per-component MeterProvider when the scope carries a
// component ID, and to the base provider otherwise. opts are forwarded
// unchanged so the instrumentation scope keeps every attribute the collector
// injected.
func (l *lifecycleMeterProvider) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	id := componentIDFromMeterOptions(opts...)
	if id == "" {
		if l.base == nil {
			return nil
		}
		return l.base.Meter(name, opts...)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	sub, ok := l.subs[id]
	if !ok {
		readers := make([]*sdkmetric.ManualReader, len(l.specs))
		mpOpts := make([]sdkmetric.Option, 0, len(l.specs)+1)
		for i, spec := range l.specs {
			readers[i] = sdkmetric.NewManualReader(
				sdkmetric.WithTemporalitySelector(spec.temporality),
				sdkmetric.WithAggregationSelector(spec.aggregation),
			)
			mpOpts = append(mpOpts, sdkmetric.WithReader(readers[i]))
		}
		if len(l.views) > 0 {
			mpOpts = append(mpOpts, sdkmetric.WithView(l.views...))
		}
		sub = &componentMeters{
			mp:      sdkmetric.NewMeterProvider(mpOpts...),
			readers: readers,
		}
		l.subs[id] = sub
	}
	return sub.mp.Meter(name, opts...)
}

// ComponentStopped disposes of every meter, instrument and aggregator created
// for the given component. It is driven by componentstatus.StatusStopped, which
// the service reports for each receiver torn down by a partial reload as well
// as on a full shutdown.
func (l *lifecycleMeterProvider) ComponentStopped(ctx context.Context, componentID string) {
	l.mu.Lock()
	sub, ok := l.subs[componentID]
	delete(l.subs, componentID)
	l.mu.Unlock()

	if ok {
		_ = sub.mp.Shutdown(ctx)
	}
}

// LiveComponents reports how many components currently hold meters. Used by
// tests and diagnostics.
func (l *lifecycleMeterProvider) LiveComponents() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.subs)
}

// NewProducer registers a consumer of component-scoped metrics and returns the
// sdkmetric.Producer to attach to that consumer's reader, so those metrics
// reach the same exporters they did when a single MeterProvider owned them.
// Readers do not re-aggregate Producer output, so the producer aggregates with
// the given selectors to match the reader it feeds; nil selectors mean the SDK
// defaults (cumulative, default aggregation). All producers must be created
// before the first component meter: sub-provider pipelines are built from the
// consumers known at that point, and a later producer would see no data.
func (l *lifecycleMeterProvider) NewProducer(
	temporality sdkmetric.TemporalitySelector,
	aggregation sdkmetric.AggregationSelector,
) sdkmetric.Producer {
	if temporality == nil {
		temporality = sdkmetric.DefaultTemporalitySelector
	}
	if aggregation == nil {
		aggregation = sdkmetric.DefaultAggregationSelector
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.specs = append(l.specs, readerSpec{temporality: temporality, aggregation: aggregation})
	return &componentMetricsProducer{lp: l, idx: len(l.specs) - 1}
}

// componentMetricsProducer implements sdkmetric.Producer for one consumer
// registered via NewProducer: it collects that consumer's dedicated reader on
// every live component sub-provider.
type componentMetricsProducer struct {
	lp  *lifecycleMeterProvider
	idx int
}

func (p *componentMetricsProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	p.lp.mu.Lock()
	subs := make([]*componentMeters, 0, len(p.lp.subs))
	for _, sub := range p.lp.subs {
		subs = append(subs, sub)
	}
	p.lp.mu.Unlock()

	var (
		out  []metricdata.ScopeMetrics
		errs []error
	)
	for _, sub := range subs {
		if p.idx >= len(sub.readers) {
			// The sub-provider was built before this consumer registered, so it
			// has no pipeline for it. Does not happen in practice: every
			// producer is created during factory construction, before any
			// component creates a meter.
			continue
		}
		var rm metricdata.ResourceMetrics
		if err := sub.readers[p.idx].Collect(ctx, &rm); err != nil {
			// A component shut down between the snapshot above and this call
			// collects as ErrReaderShutdown; that is expected, not an error.
			if errors.Is(err, sdkmetric.ErrReaderShutdown) {
				continue
			}
			errs = append(errs, err)
			continue
		}
		out = append(out, rm.ScopeMetrics...)
	}
	return out, errors.Join(errs...)
}

func (l *lifecycleMeterProvider) Shutdown(ctx context.Context) error {
	l.mu.Lock()
	subs := l.subs
	l.subs = make(map[string]*componentMeters)
	l.mu.Unlock()

	var errs []error
	for _, sub := range subs {
		if err := sub.mp.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if l.base != nil {
		if err := l.base.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func componentIDFromMeterOptions(opts ...metric.MeterOption) string {
	attrs := metric.NewMeterConfig(opts...).InstrumentationAttributes()
	for _, kv := range attrs.ToSlice() {
		if string(kv.Key) == otelComponentIDKey {
			return kv.Value.AsString()
		}
	}
	return ""
}
