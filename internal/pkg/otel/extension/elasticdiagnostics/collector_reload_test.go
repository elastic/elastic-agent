// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/service/telemetry"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// This test runs a real collector to check the assumption the elastic_diagnostics
// extension relies on: that the service reports componentstatus.StatusStopped for a
// receiver a partial reload tears down, so the extension can drop that receiver's
// diagnostic hooks. Beat receivers register hooks the same way hookReceiver does
// here, keyed by their own component ID.

var hookReceiverType = component.MustNewType("hooktest")

// diagRegistrar is the subset of the elastic_diagnostics extension beat
// receivers use to register their hooks (see otelmanager.DiagnosticExtension).
type diagRegistrar interface {
	RegisterDiagnosticHook(componentName string, description string, filename string, contentType string, hook func() []byte)
}

// hookReceiver registers a diagnostic hook under its own component ID when it
// starts, exactly as a beat receiver does, and otherwise does nothing.
type hookReceiver struct {
	id string
}

func (r *hookReceiver) Start(_ context.Context, host component.Host) error {
	for _, ext := range host.GetExtensions() {
		if reg, ok := ext.(diagRegistrar); ok {
			id := r.id
			reg.RegisterDiagnosticHook(id, "test hook", "beat_metrics.json", "application/json",
				func() []byte { return []byte(id) })
		}
	}
	return nil
}

func (r *hookReceiver) Shutdown(context.Context) error { return nil }

func hookReceiverFactory() receiver.Factory {
	return receiver.NewFactory(
		hookReceiverType,
		func() component.Config { return &struct{}{} },
		receiver.WithMetrics(
			func(_ context.Context, set receiver.Settings, _ component.Config, _ consumer.Metrics) (receiver.Metrics, error) {
				return &hookReceiver{id: set.ID.String()}, nil
			}, component.StabilityLevelDevelopment),
	)
}

func diagnosticsTestFactories() (otelcol.Factories, error) {
	var factories otelcol.Factories
	var err error
	// The service requires a telemetry factory; this one's defaults are a noop
	// logger, meter and tracer provider, which is all the test needs.
	factories.Telemetry = telemetry.NewFactory(func() component.Config { return &struct{}{} })
	if factories.Receivers, err = otelcol.MakeFactoryMap[receiver.Factory](hookReceiverFactory()); err != nil {
		return otelcol.Factories{}, err
	}
	if factories.Exporters, err = otelcol.MakeFactoryMap[exporter.Factory](exportertest.NewNopFactory()); err != nil {
		return otelcol.Factories{}, err
	}
	if factories.Extensions, err = otelcol.MakeFactoryMap[extension.Factory](NewFactory()); err != nil {
		return otelcol.Factories{}, err
	}
	return factories, nil
}

// reloadProvider serves a config that the test can replace, notifying the
// collector of the change the same way the agent's config provider does.
type reloadProvider struct {
	mu       sync.Mutex
	cfg      map[string]any
	watchers []confmap.WatcherFunc
}

func (p *reloadProvider) Retrieve(_ context.Context, _ string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if watcher != nil {
		p.watchers = append(p.watchers, watcher)
	}
	return confmap.NewRetrieved(p.cfg)
}

func (p *reloadProvider) Scheme() string { return "testcfg" }

func (p *reloadProvider) Shutdown(context.Context) error { return nil }

// set replaces the served config and tells the collector to reload it.
func (p *reloadProvider) set(cfg map[string]any) {
	p.mu.Lock()
	watchers := p.watchers
	p.cfg = cfg
	p.watchers = nil
	p.mu.Unlock()
	for _, w := range watchers {
		w(&confmap.ChangeEvent{})
	}
}

func collectorConfig(receiverID, endpoint string) map[string]any {
	return map[string]any{
		"receivers":  map[string]any{receiverID: map[string]any{}},
		"exporters":  map[string]any{"nop": map[string]any{}},
		"extensions": map[string]any{"elastic_diagnostics": map[string]any{"endpoint": endpoint}},
		"service": map[string]any{
			"extensions": []any{"elastic_diagnostics"},
			"pipelines": map[string]any{
				"metrics": map[string]any{
					"receivers": []any{receiverID},
					"exporters": []any{"nop"},
				},
			},
		},
	}
}

// componentDiagnosticsOverSocket asks a running extension for diagnostics over
// its endpoint and returns the component entries as component ID -> content.
func componentDiagnosticsOverSocket(ctx context.Context, httpClient *http.Client) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/diagnostics", nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed Response
	if err := json.Unmarshal(b, &parsed); err != nil {
		return nil, err
	}
	got := make(map[string]string, len(parsed.ComponentDiagnostics))
	for _, r := range parsed.ComponentDiagnostics {
		got[r.Name] = string(r.Content)
	}
	return got, nil
}

func TestDiagnosticHooksDroppedOnPartialReload(t *testing.T) {
	for _, id := range []string{"service.partialReload", "service.partialReloadReceivers"} {
		var was bool
		featuregate.GlobalRegistry().VisitAll(func(g *featuregate.Gate) {
			if g.ID() == id {
				was = g.IsEnabled()
			}
		})
		require.NoError(t, featuregate.GlobalRegistry().Set(id, true))
		t.Cleanup(func() {
			require.NoError(t, featuregate.GlobalRegistry().Set(id, was))
		})
	}

	endpoint := utils.SocketURLWithFallback("diag.sock", t.TempDir())
	provider := &reloadProvider{cfg: collectorConfig("hooktest/a", endpoint)}

	settings := otelcol.CollectorSettings{
		Factories: diagnosticsTestFactories,
		BuildInfo: component.NewDefaultBuildInfo(),
		ConfigProviderSettings: otelcol.ConfigProviderSettings{
			ResolverSettings: confmap.ResolverSettings{
				URIs: []string{"testcfg:config"},
				ProviderFactories: []confmap.ProviderFactory{
					confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider { return provider }),
				},
				DefaultScheme: "testcfg",
			},
		},
		DisableGracefulShutdown: true,
	}
	col, err := otelcol.NewCollector(settings)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, col.Run(ctx))
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()

	httpClient := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, endpoint)
		},
	}}

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		got, err := componentDiagnosticsOverSocket(ctx, httpClient)
		require.NoError(collect, err)
		assert.Equal(collect, map[string]string{"hooktest/a": "hooktest/a"}, got)
	}, 30*time.Second, 50*time.Millisecond, "the first receiver's hook should be registered")

	// Replace the receiver, which a partial reload stops and rebuilds under a new ID.
	provider.set(collectorConfig("hooktest/b", endpoint))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		got, err := componentDiagnosticsOverSocket(ctx, httpClient)
		require.NoError(collect, err)
		assert.Equal(collect, map[string]string{"hooktest/b": "hooktest/b"}, got,
			"the stopped receiver's hook should be gone and only the new receiver's hook left")
	}, 30*time.Second, 50*time.Millisecond)
}
