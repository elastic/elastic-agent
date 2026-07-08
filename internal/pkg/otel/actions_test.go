// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

// startMockActionsServer stands up an HTTP server on the diagnostics extension
// socket handling POST /actions, mimicking the elasticdiagnostics extension for
// testing PerformActionExt without a real EDOT collector.
func startMockActionsServer(t *testing.T, handle func(elasticdiagnostics.ActionRequest) (int, elasticdiagnostics.ActionResponse)) *http.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/actions", func(w http.ResponseWriter, r *http.Request) {
		var req elasticdiagnostics.ActionRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		status, resp := handle(req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	})

	l, err := ipc.CreateListener(logger.NewWithoutConfig(""), paths.DiagnosticsExtensionSocket())
	require.NoError(t, err)
	server := &http.Server{Handler: mux} //nolint:gosec // this is a test
	go func() {
		_ = server.Serve(l)
	}()
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestPerformActionExt(t *testing.T) {
	tempDir := t.TempDir()
	prevSocket := paths.DiagnosticsExtensionSocket()
	paths.SetDiagnosticsExtensionSocket(paths.SocketFromPath(runtime.GOOS, tempDir, "test-actions.sock"))
	t.Cleanup(func() { paths.SetDiagnosticsExtensionSocket(prevSocket) })

	t.Run("successful action round-trips result", func(t *testing.T) {
		startMockActionsServer(t, func(req elasticdiagnostics.ActionRequest) (int, elasticdiagnostics.ActionResponse) {
			require.Equal(t, "osquery-default", req.ComponentID)
			require.Equal(t, "osquery", req.Name)
			require.Equal(t, map[string]interface{}{"id": "abc"}, req.Params)
			return http.StatusOK, elasticdiagnostics.ActionResponse{Result: map[string]interface{}{"count": float64(1)}}
		})

		res, err := PerformActionExt(context.Background(), "osquery-default", "osquery", map[string]interface{}{"id": "abc"})
		require.NoError(t, err)
		require.Equal(t, map[string]interface{}{"count": float64(1)}, res)
	})

	t.Run("handler error is surfaced", func(t *testing.T) {
		startMockActionsServer(t, func(req elasticdiagnostics.ActionRequest) (int, elasticdiagnostics.ActionResponse) {
			return http.StatusOK, elasticdiagnostics.ActionResponse{Error: "query failed"}
		})

		res, err := PerformActionExt(context.Background(), "osquery-default", "osquery", nil)
		require.Error(t, err)
		require.EqualError(t, err, "query failed")
		require.Nil(t, res)
	})

	t.Run("no handler registered for component", func(t *testing.T) {
		startMockActionsServer(t, func(req elasticdiagnostics.ActionRequest) (int, elasticdiagnostics.ActionResponse) {
			return http.StatusNotFound, elasticdiagnostics.ActionResponse{Error: "no action handler registered for component \"osquery-default\""}
		})

		_, err := PerformActionExt(context.Background(), "osquery-default", "osquery", nil)
		require.Error(t, err)
	})

	t.Run("EDOT not running", func(t *testing.T) {
		paths.SetDiagnosticsExtensionSocket(paths.SocketFromPath(runtime.GOOS, t.TempDir(), "does-not-exist.sock"))
		_, err := PerformActionExt(context.Background(), "osquery-default", "osquery", nil)
		require.Error(t, err)
	})
}
