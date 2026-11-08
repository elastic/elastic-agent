// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/service/telemetry"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
	otelconf "go.opentelemetry.io/contrib/otelconf/v0.3.0"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
)

// testScopeName stands in for an instrumentation scope a component would use.
const testScopeName = "github.com/elastic/elastic-agent/internal/edot/internaltelemetry/test"

// attrInjector mimics the collector's componentattribute wrapper: it injects
// the component ID as an instrumentation *scope* attribute, which is what makes
// the SDK hand out a distinct meter per component instance.
type attrInjector struct {
	embedded.MeterProvider
	inner metric.MeterProvider
	attrs []attribute.KeyValue
}

func (a attrInjector) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	conf := metric.NewMeterConfig(opts...)
	set := conf.InstrumentationAttributes()
	merged := append(append([]attribute.KeyValue{}, a.attrs...), set.ToSlice()...)
	opts = append(opts, metric.WithInstrumentationAttributes(merged...))
	return a.inner.Meter(name, opts...)
}

func asComponent(mp metric.MeterProvider, id string) metric.MeterProvider {
	return attrInjector{
		inner: mp,
		attrs: []attribute.KeyValue{
			attribute.String(otelComponentIDKey, id),
			attribute.String("otelcol.component.kind", "receiver"),
		},
	}
}

// newTestProvider builds a provider through the real factory. Passing a
// prometheus port of 0 lets the OS pick one, which keeps parallel tests apart.
func newTestProvider(t *testing.T, promPort int, views []otelconf.View) telemetry.MeterProvider {
	t.Helper()

	// Bypass the NewFactory singleton so each test gets its own factory, and
	// install it globally so ComponentStopped reaches this one.
	wf := &wrappedFactory{Factory: otelconftelemetry.NewFactory()}
	globalFactory.Store(wf)
	t.Cleanup(func() { globalFactory.Store(nil) })

	cfg, ok := otelconftelemetry.NewFactory().CreateDefaultConfig().(*otelconftelemetry.Config)
	if !ok {
		t.Fatal("unexpected telemetry config type")
	}
	for i := range cfg.Metrics.MeterProvider.Readers {
		if r := cfg.Metrics.MeterProvider.Readers[i]; r.Pull != nil && r.Pull.Exporter.Prometheus != nil {
			r.Pull.Exporter.Prometheus.Host = ptr("localhost")
			r.Pull.Exporter.Prometheus.Port = ptr(promPort)
		}
	}
	cfg.Metrics.Views = views

	res := pcommon.NewResource()
	res.Attributes().PutStr("service.name", "internaltelemetry-test")
	set := telemetry.MeterSettings{
		Settings:     telemetry.Settings{BuildInfo: component.NewDefaultBuildInfo(), Resource: &res},
		Logger:       zap.NewNop(),
		DefaultViews: func(configtelemetry.Level) []otelconf.View { return nil },
	}

	mp, err := wf.CreateMeterProvider(context.Background(), set, cfg)
	if err != nil {
		t.Fatalf("CreateMeterProvider: %v", err)
	}
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	return mp
}

// observeCounter registers one async counter on mp reporting value 1. It
// returns the instrument name.
func observeCounter(t *testing.T, mp metric.MeterProvider, name string) string {
	t.Helper()
	meter := mp.Meter(testScopeName)
	inst, err := meter.Int64ObservableCounter(name)
	if err != nil {
		t.Fatalf("instrument %q: %v", name, err)
	}
	if _, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(inst, 1)
		return nil
	}, inst); err != nil {
		t.Fatalf("callback %q: %v", name, err)
	}
	return name
}

// collectedComponentIDs returns the component IDs present in the scope
// attributes of everything the manual reader collects.
func collectedComponentIDs(t *testing.T) map[string]bool {
	t.Helper()
	rm, err := ReadMetrics(context.Background())
	if err != nil {
		t.Fatalf("ReadMetrics: %v", err)
	}
	ids := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, kv := range sm.Scope.Attributes.ToSlice() {
			if string(kv.Key) == otelComponentIDKey {
				ids[kv.Value.AsString()] = true
			}
		}
	}
	return ids
}

func collectedMetricNames(t *testing.T) map[string]bool {
	t.Helper()
	rm, err := ReadMetrics(context.Background())
	if err != nil {
		t.Fatalf("ReadMetrics: %v", err)
	}
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
			var _ metricdata.Aggregation = m.Data
		}
	}
	return names
}

// TestComponentMetersReleasedOnStop is the core guard: a component that stops
// must leave nothing behind. Without this the collector retains every component
// instance it has ever built.
func TestComponentMetersReleasedOnStop(t *testing.T) {
	mp := newTestProvider(t, 0, nil)

	const idA, idB = "receiver/a", "receiver/b"
	observeCounter(t, asComponent(mp, idA), "metric_a")
	observeCounter(t, asComponent(mp, idB), "metric_b")

	if got := LiveMeterComponents(); got != 2 {
		t.Fatalf("expected 2 live meter components, got %d", got)
	}
	if ids := collectedComponentIDs(t); !ids[idA] || !ids[idB] {
		t.Fatalf("expected both components reporting, got %v", ids)
	}

	ComponentStopped(context.Background(), idA)

	if got := LiveMeterComponents(); got != 1 {
		t.Errorf("expected 1 live meter component after stop, got %d", got)
	}
	ids := collectedComponentIDs(t)
	if ids[idA] {
		t.Errorf("stopped component %q is still reporting", idA)
	}
	if !ids[idB] {
		t.Errorf("running component %q stopped reporting", idB)
	}

	ComponentStopped(context.Background(), idB)
	if got := LiveMeterComponents(); got != 0 {
		t.Errorf("expected 0 live meter components, got %d", got)
	}
}

// TestScopeAttributesPreserved guards granularity: per-component providers must
// forward the injected scope attributes untouched.
func TestScopeAttributesPreserved(t *testing.T) {
	mp := newTestProvider(t, 0, nil)

	const id = "receiver/with-instance-identity"
	observeCounter(t, asComponent(mp, id), "metric_scope")

	if ids := collectedComponentIDs(t); !ids[id] {
		t.Errorf("component id missing from collected scope attributes: %v", ids)
	}
}

// TestNonComponentScopeUsesBaseProvider checks that service-level telemetry,
// which carries no component ID, is not given a per-component provider.
func TestNonComponentScopeUsesBaseProvider(t *testing.T) {
	mp := newTestProvider(t, 0, nil)

	observeCounter(t, mp, "metric_service_level")

	if got := LiveMeterComponents(); got != 0 {
		t.Errorf("scope without a component ID created %d per-component provider(s)", got)
	}
	if !collectedMetricNames(t)["metric_service_level"] {
		t.Error("service-level metric is missing from collected output")
	}
}

// TestViewsApplyToComponentProviders guards the view wiring. Producer output
// bypasses the base provider's pipelines, so a per-component provider that did
// not get the configured views would report metrics the telemetry level drops.
func TestViewsApplyToComponentProviders(t *testing.T) {
	dropped := otelconf.View{
		Selector: &otelconf.ViewSelector{
			MeterName:      ptr(testScopeName),
			InstrumentName: ptr("metric_dropped"),
		},
		Stream: &otelconf.ViewStream{
			Aggregation: &otelconf.ViewStreamAggregation{Drop: otelconf.ViewStreamAggregationDrop{}},
		},
	}
	mp := newTestProvider(t, 0, []otelconf.View{dropped})

	comp := asComponent(mp, "receiver/views")
	observeCounter(t, comp, "metric_dropped")
	observeCounter(t, comp, "metric_kept")

	names := collectedMetricNames(t)
	if names["metric_dropped"] {
		t.Error("drop view was not applied to the per-component provider")
	}
	if !names["metric_kept"] {
		t.Error("view dropped a metric it should not have")
	}
}

// TestConfigBuiltReaderSeesComponentMetrics guards the otelconf dependency:
// component metrics live in providers we create, and reach readers built from
// configuration only through a Producer, which requires
// otelconf.WithMetricProducers. Scrapes the real prometheus endpoint.
func TestConfigBuiltReaderSeesComponentMetrics(t *testing.T) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()

	mp := newTestProvider(t, port, nil)

	const id = "receiver/prometheus"
	observeCounter(t, asComponent(mp, id), "metric_scraped")

	body := scrapeMetrics(t, port)
	if !strings.Contains(body, "metric_scraped") {
		t.Fatalf("component metric missing from prometheus output (%d bytes)", len(body))
	}

	ComponentStopped(context.Background(), id)
	if body = scrapeMetrics(t, port); strings.Contains(body, "metric_scraped") {
		t.Error("stopped component still present in prometheus output")
	}
}

func scrapeMetrics(t *testing.T, port int) string {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape body: %v", err)
	}
	return string(b)
}
