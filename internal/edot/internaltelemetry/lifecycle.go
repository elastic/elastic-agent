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

	mu   sync.Mutex
	subs map[string]*componentMeters
}

type componentMeters struct {
	mp     *sdkmetric.MeterProvider
	reader *sdkmetric.ManualReader
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
		reader := sdkmetric.NewManualReader()
		mpOpts := []sdkmetric.Option{sdkmetric.WithReader(reader)}
		if len(l.views) > 0 {
			mpOpts = append(mpOpts, sdkmetric.WithView(l.views...))
		}
		sub = &componentMeters{
			mp:     sdkmetric.NewMeterProvider(mpOpts...),
			reader: reader,
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

// Produce implements sdkmetric.Producer. It is registered on every reader that
// feeds the base provider, so component-scoped metrics reach the same exporters
// they did when a single MeterProvider owned them.
func (l *lifecycleMeterProvider) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	l.mu.Lock()
	subs := make([]*componentMeters, 0, len(l.subs))
	for _, sub := range l.subs {
		subs = append(subs, sub)
	}
	l.mu.Unlock()

	var (
		out  []metricdata.ScopeMetrics
		errs []error
	)
	for _, sub := range subs {
		var rm metricdata.ResourceMetrics
		if err := sub.reader.Collect(ctx, &rm); err != nil {
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
