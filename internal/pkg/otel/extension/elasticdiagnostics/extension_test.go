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
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensioncapabilities"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"

	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics/internal/metadata"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestExtension(t *testing.T) {
	temp := t.TempDir()
	config := createDefaultConfig().(*Config)
	config.Endpoint = utils.SocketURLWithFallback("edot.sock", temp)

	ext, err := NewFactory().Create(context.Background(), extension.Settings{
		TelemetrySettings: component.TelemetrySettings{
			Logger: zap.NewNop(),
		},
		ID: component.NewID(metadata.Type),
	}, config)
	require.NoError(t, err)
	require.NotNil(t, ext)

	require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
	defer func() {
		require.NoError(t, ext.Shutdown(context.Background()))
	}()

	// mock a few calls to RegisterDiagnosticHook
	diagExt := ext.(*diagnosticsExtension)
	diagExt.RegisterDiagnosticHook("test_component",
		"Test Hook",
		"test.json",
		"application/json",
		func() []byte {
			return []byte("diagnostic data")
		},
	)

	diagExt.RegisterDiagnosticHook("test_component2",
		"Test Hook2",
		"test2.json",
		"application/json",
		func() []byte {
			return []byte("diagnostic data 2")
		},
	)

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, config.Endpoint)
		},
	}
	client := &http.Client{Transport: tr}

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/diagnostics?cpu=true&cpuduration=5s", nil)
		require.NoError(collect, err)
		resp, err := client.Do(req)
		require.NoError(collect, err)
		require.Equal(collect, http.StatusOK, resp.StatusCode)

		b, err := io.ReadAll(resp.Body)
		require.NoError(collect, err)
		res := Response{}

		// test that the response can be unmarshalled
		require.NoErrorf(collect, json.Unmarshal(b, &res), "failed to unmarshal response: %s", string(b))
		require.NotEmpty(collect, res.GlobalDiagnostics)
		require.NotEmpty(collect, res.ComponentDiagnostics)
		foundCPU := false
		foundEnv := false
		for _, global := range res.GlobalDiagnostics {
			switch global.Name {
			case "cpu":
				foundCPU = true
			case "environment":
				foundEnv = true
				require.Equal(collect, "edot/environment.yaml", global.Filename)
				require.Equal(collect, "application/yaml", global.ContentType)
			default:
				if strings.HasSuffix(global.Filename, "profile.gz") {
					verifyPprof(t, global.Content)
				}
			}
		}
		require.True(collect, foundCPU, "cpu.pprof not found in global diagnostics")
		require.True(collect, foundEnv, "environment not found in global diagnostics")

		for _, comp := range res.ComponentDiagnostics {
			switch comp.Name {
			case "test_component":
				require.Equal(collect, "test.json", comp.Filename)
				require.Equal(collect, "application/json", comp.ContentType)
				require.Equal(collect, "Test Hook", comp.Description)
				require.Equal(collect, []byte("diagnostic data"), comp.Content)
			case "test_component2":
				require.Equal(collect, "test2.json", comp.Filename)
				require.Equal(collect, "application/json", comp.ContentType)
				require.Equal(collect, "Test Hook2", comp.Description)
				require.Equal(collect, []byte("diagnostic data 2"), comp.Content)
			}
		}
		require.NoError(collect, resp.Body.Close())
	}, 10*time.Second, 1*time.Millisecond, "extension did not start in time")
}

func TestExtension_NotifyConfigSnapshot(t *testing.T) {
	ext, err := NewFactory().Create(context.Background(), extension.Settings{
		TelemetrySettings: component.TelemetrySettings{
			Logger: zap.NewNop(),
		},
		ID: component.NewID(metadata.Type),
	}, createDefaultConfig())
	require.NoError(t, err)
	diagExt := ext.(*diagnosticsExtension)
	// Register the built-in hooks without starting the HTTP server.
	diagExt.registerGlobalDiagnostics()

	configHook, ok := diagExt.globalHooks["collector_config"]
	require.True(t, ok, "collector_config diagnostic hook not registered")
	require.Equal(t, "edot/otel-merged-actual.yaml", configHook.filename)

	// Before the collector notifies the extension there is no config to report.
	assert.Equal(t, "no active OTel Configuration", string(configHook.hook()))

	effective := confmap.NewFromStringMap(map[string]any{
		"receivers": map[string]any{"nop": map[string]any{}},
		"exporters": map[string]any{"nop": map[string]any{"api_key": "secret"}},
	})
	unexpanded := confmap.NewFromStringMap(map[string]any{
		"receivers": map[string]any{"nop": map[string]any{}},
		"exporters": map[string]any{"nop": map[string]any{"api_key": "${env:API_KEY}"}},
	})
	require.NoError(t, diagExt.NotifyConfigSnapshot(context.Background(),
		extensioncapabilities.NewConfigSnapshot(effective, unexpanded)))

	// The diagnostic reports the effective (expanded) configuration.
	var got map[string]any
	require.NoError(t, yaml.Unmarshal(configHook.hook(), &got))
	assert.Equal(t, effective.ToStringMap(), got)

	// A subsequent notification replaces the stored configuration.
	updated := confmap.NewFromStringMap(map[string]any{
		"receivers": map[string]any{"otlp": map[string]any{}},
	})
	require.NoError(t, diagExt.NotifyConfigSnapshot(context.Background(),
		extensioncapabilities.NewConfigSnapshot(updated, updated)))
	got = nil
	require.NoError(t, yaml.Unmarshal(configHook.hook(), &got))
	assert.Equal(t, updated.ToStringMap(), got)

	// A nil snapshot clears the stored configuration instead of panicking.
	require.NoError(t, diagExt.NotifyConfigSnapshot(context.Background(), nil))
	assert.Equal(t, "no active OTel Configuration", string(configHook.hook()))
}

func verifyPprof(t *testing.T, content []byte) {
	prof, err := profile.ParseData(content)
	require.NoError(t, err)
	require.NotNil(t, prof)
}

func TestExtension_Actions(t *testing.T) {
	temp := t.TempDir()
	config := createDefaultConfig().(*Config)
	config.Endpoint = utils.SocketURLWithFallback("edot-actions.sock", temp)

	ext, err := NewFactory().Create(context.Background(), extension.Settings{
		TelemetrySettings: component.TelemetrySettings{
			Logger: zap.NewNop(),
		},
		ID: component.NewID(metadata.Type),
	}, config)
	require.NoError(t, err)
	require.NotNil(t, ext)

	require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
	defer func() {
		require.NoError(t, ext.Shutdown(context.Background()))
	}()

	diagExt := ext.(*diagnosticsExtension)

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, config.Endpoint)
		},
	}
	httpClient := &http.Client{Transport: tr}

	postAction := func(t *testing.T, actionReq ActionRequest) (int, ActionResponse) {
		t.Helper()
		body, err := json.Marshal(actionReq)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://localhost/actions", strings.NewReader(string(body)))
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		var actionResp ActionResponse
		if len(b) > 0 {
			require.NoError(t, json.Unmarshal(b, &actionResp))
		}
		return resp.StatusCode, actionResp
	}

	t.Run("no handler registered", func(t *testing.T) {
		status, _ := postAction(t, ActionRequest{ComponentID: "osquery-default", Name: "osquery", Params: map[string]any{}})
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("handler invoked and result round-trips", func(t *testing.T) {
		var receivedParams map[string]any
		require.NoError(t, diagExt.RegisterActionHandler("osquerybeatreceiver/_agent-component/osquery-default/osquery-default",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				receivedParams = params
				return map[string]any{"count": float64(3)}, nil
			}))

		status, resp := postAction(t, ActionRequest{
			ComponentID: "osquery-default",
			Name:        "osquery",
			Params:      map[string]any{"id": "abc"},
		})
		assert.Equal(t, http.StatusOK, status)
		assert.Empty(t, resp.Error)
		assert.Equal(t, map[string]any{"count": float64(3)}, resp.Result)
		assert.Equal(t, map[string]any{"id": "abc"}, receivedParams)
	})

	t.Run("handler error is surfaced but request still succeeds", func(t *testing.T) {
		require.NoError(t, diagExt.RegisterActionHandler("osquerybeatreceiver/_agent-component/osquery-error/osquery-error",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				return nil, assert.AnError
			}))

		status, resp := postAction(t, ActionRequest{ComponentID: "osquery-error", Name: "osquery"})
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, assert.AnError.Error(), resp.Error)
	})

	t.Run("unregistered handler is no longer reachable", func(t *testing.T) {
		diagExt.UnregisterActionHandler("osquerybeatreceiver/_agent-component/osquery-default/osquery-default")
		status, _ := postAction(t, ActionRequest{ComponentID: "osquery-default", Name: "osquery"})
		assert.Equal(t, http.StatusNotFound, status)
	})

	// A component's input normally runs as one OTel receiver per stream.
	// If such a multi-receiver component's beat ever registered a custom action, every stream's
	// receiver would register under the same elastic-agent component ID.
	// There is no per-stream targeting info in a Fleet action, so this must be
	// treated as an error rather than silently routing to whichever receiver
	// registered last.
	t.Run("multiple receivers for one component is ambiguous", func(t *testing.T) {
		// The first receiver to register is unaffected: nothing is ambiguous yet.
		err := diagExt.RegisterActionHandler("filebeatreceiver/_agent-component/filestream-default/stream-1",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				return map[string]any{"stream": "1"}, nil
			})
		require.NoError(t, err)

		// The second, conflicting receiver must be told immediately — via its
		// own RegisterActionHandler call, i.e. at registration time on the
		// beat side — not only the next time Fleet dispatches an action.
		err = diagExt.RegisterActionHandler("filebeatreceiver/_agent-component/filestream-default/stream-2",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				return map[string]any{"stream": "2"}, nil
			})
		require.Error(t, err)
		assert.ErrorIs(t, err, errAmbiguousActionRouting)
		assert.Contains(t, err.Error(), "filestream-default")
		assert.Contains(t, err.Error(), "single_receiver: true")

		// The same ambiguity must independently be caught at action-processing
		// time too, in case a future caller of RegisterActionHandler ignores
		// its returned error.
		status, resp := postAction(t, ActionRequest{ComponentID: "filestream-default", Name: "some-action"})
		assert.Equal(t, http.StatusConflict, status)
		assert.Contains(t, resp.Error, "ambiguous action routing")
		assert.Contains(t, resp.Error, "filestream-default")
		assert.Contains(t, resp.Error, "single_receiver: true")

		t.Run("unregistering one receiver resolves the ambiguity", func(t *testing.T) {
			diagExt.UnregisterActionHandler("filebeatreceiver/_agent-component/filestream-default/stream-1")

			status, resp := postAction(t, ActionRequest{ComponentID: "filestream-default", Name: "some-action"})
			assert.Equal(t, http.StatusOK, status)
			assert.Equal(t, map[string]any{"stream": "2"}, resp.Result)

			diagExt.UnregisterActionHandler("filebeatreceiver/_agent-component/filestream-default/stream-2")
		})
	})

	t.Run("re-registering the same receiver replaces its handler without ambiguity", func(t *testing.T) {
		const receiverName = "osquerybeatreceiver/_agent-component/osquery-restart/osquery-restart"
		err := diagExt.RegisterActionHandler(receiverName, func(ctx context.Context, params map[string]any) (map[string]any, error) {
			return map[string]any{"version": "1"}, nil
		})
		require.NoError(t, err)
		// Simulate the beat process restarting and re-registering under the
		// same receiver name — this must cleanly replace, not accumulate, and
		// must not be reported as ambiguous.
		err = diagExt.RegisterActionHandler(receiverName, func(ctx context.Context, params map[string]any) (map[string]any, error) {
			return map[string]any{"version": "2"}, nil
		})
		require.NoError(t, err)

		status, resp := postAction(t, ActionRequest{ComponentID: "osquery-restart", Name: "osquery"})
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, map[string]any{"version": "2"}, resp.Result)
	})

	t.Run("GET is not allowed", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://localhost/actions", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer func() { require.NoError(t, resp.Body.Close()) }()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	})
}

func newTestDiagnosticsExtension(t *testing.T) *diagnosticsExtension {
	t.Helper()
	ext, err := newExtension(t.Context(), extension.Settings{
		TelemetrySettings: component.TelemetrySettings{Logger: zap.NewNop()},
	}, createDefaultConfig())
	require.NoError(t, err, "failed to create extension")
	return ext.(*diagnosticsExtension)
}

// componentDiagnostics calls ServeHTTP and returns "<component>/<filename>" -> content.
func componentDiagnostics(t *testing.T, d *diagnosticsExtension) map[string]string {
	t.Helper()
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/diagnostics", nil))
	require.Equal(t, http.StatusOK, rec.Code, "unexpected status from ServeHTTP")
	var resp Response
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), "failed to decode diagnostics response")
	got := make(map[string]string, len(resp.ComponentDiagnostics))
	for _, r := range resp.ComponentDiagnostics {
		key := r.Name + "/" + r.Filename
		_, dup := got[key]
		assert.False(t, dup, "duplicate diagnostics entry %q", key)
		got[key] = string(r.Content)
	}
	return got
}

// serveDiagnostics calls ServeHTTP without asserting anything, for use outside the test goroutine.
func serveDiagnostics(ctx context.Context, d *diagnosticsExtension) {
	d.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, http.MethodGet, "/diagnostics", nil))
}

func staticHook(content string) func() []byte {
	return func() []byte { return []byte(content) }
}

func TestDiagnosticHooks_RegisterUnregister(t *testing.T) {
	d := newTestDiagnosticsExtension(t)

	d.RegisterDiagnosticHook("comp1", "metrics", "beat_metrics.json", "application/json", staticHook("comp1 metrics"))
	d.RegisterDiagnosticHook("comp1", "inputs", "input_metrics.json", "application/json", staticHook("comp1 inputs"))
	d.RegisterDiagnosticHook("comp2", "metrics", "beat_metrics.json", "application/json", staticHook("comp2 metrics"))
	assert.Equal(t, map[string]string{
		"comp1/beat_metrics.json":  "comp1 metrics",
		"comp1/input_metrics.json": "comp1 inputs",
		"comp2/beat_metrics.json":  "comp2 metrics",
	}, componentDiagnostics(t, d), "all registered hooks should be served")

	d.UnregisterDiagnosticHooks("comp1")
	assert.Equal(t, map[string]string{
		"comp2/beat_metrics.json": "comp2 metrics",
	}, componentDiagnostics(t, d), "comp1 hooks should be gone after unregister")
	assert.NotContains(t, d.componentHooks, "comp1", "unregistered component should not keep an entry")

	d.UnregisterDiagnosticHooks("unknown")
	assert.Len(t, componentDiagnostics(t, d), 1, "unregistering an unknown component should be a no-op")

	d.RegisterDiagnosticHook("comp1", "metrics", "beat_metrics.json", "application/json", staticHook("comp1 metrics v2"))
	assert.Equal(t, map[string]string{
		"comp1/beat_metrics.json": "comp1 metrics v2",
		"comp2/beat_metrics.json": "comp2 metrics",
	}, componentDiagnostics(t, d), "a component should be able to register again after unregister")
}

func TestDiagnosticHooks_ReRegisterReplaces(t *testing.T) {
	d := newTestDiagnosticsExtension(t)

	for i := range 100 {
		d.RegisterDiagnosticHook("comp1", "metrics", "beat_metrics.json", "application/json", staticHook(fmt.Sprintf("v%d", i)))
	}
	d.RegisterDiagnosticHook("comp1", "inputs", "input_metrics.json", "application/json", staticHook("inputs"))

	assert.Len(t, d.componentHooks["comp1"], 2, "re-registering the same filename should not add hooks")
	assert.Equal(t, map[string]string{
		"comp1/beat_metrics.json":  "v99",
		"comp1/input_metrics.json": "inputs",
	}, componentDiagnostics(t, d), "the latest registration should win")
}

func TestDiagnosticHooks_Concurrent(t *testing.T) {
	d := newTestDiagnosticsExtension(t)

	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			name := fmt.Sprintf("comp%d", w)
			for range 200 {
				d.RegisterDiagnosticHook(name, "metrics", "beat_metrics.json", "application/json", staticHook(name))
				d.RegisterDiagnosticHook(name, "inputs", "input_metrics.json", "application/json", staticHook(name))
				d.UnregisterDiagnosticHooks(name)
			}
		})
	}
	for range 2 {
		wg.Go(func() {
			for range 50 {
				serveDiagnostics(t.Context(), d)
			}
		})
	}
	wg.Wait()

	assert.Empty(t, d.componentHooks, "all hooks should be gone once every component unregistered")
}

func TestDiagnosticHooks_NoHookRunsAfterUnregister(t *testing.T) {
	d := newTestDiagnosticsExtension(t)

	var unregistered atomic.Bool
	d.RegisterDiagnosticHook("comp1", "metrics", "beat_metrics.json", "application/json", func() []byte {
		assert.False(t, unregistered.Load(), "hook ran after UnregisterDiagnosticHooks returned")
		return nil
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			serveDiagnostics(t.Context(), d)
		}
	}()
	d.UnregisterDiagnosticHooks("comp1")
	unregistered.Store(true)
	<-done
}
