// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"

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
		req, err := http.NewRequest(http.MethodGet, "http://localhost/diagnostics?cpu=true&cpuduration=5s", nil)
		require.NoError(collect, err)
		resp, err := client.Do(req.WithContext(context.Background()))
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
		for _, global := range res.GlobalDiagnostics {
			if global.Name == "cpu" {
				foundCPU = true
				break
			}
			if strings.HasSuffix(global.Filename, "profile.gz") {
				verifyPprof(t, global.Content)
			}
		}
		require.True(collect, foundCPU, "cpu.pprof not found in global diagnostics")

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
		diagExt.RegisterActionHandler("osquerybeatreceiver/_agent-component/osquery-default/osquery-default",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				receivedParams = params
				return map[string]any{"count": float64(3)}, nil
			})

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
		diagExt.RegisterActionHandler("osquerybeatreceiver/_agent-component/osquery-error/osquery-error",
			func(ctx context.Context, params map[string]any) (map[string]any, error) {
				return nil, assert.AnError
			})

		status, resp := postAction(t, ActionRequest{ComponentID: "osquery-error", Name: "osquery"})
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, assert.AnError.Error(), resp.Error)
	})

	t.Run("unregistered handler is no longer reachable", func(t *testing.T) {
		diagExt.UnregisterActionHandler("osquerybeatreceiver/_agent-component/osquery-default/osquery-default")
		status, _ := postAction(t, ActionRequest{ComponentID: "osquery-default", Name: "osquery"})
		assert.Equal(t, http.StatusNotFound, status)
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
