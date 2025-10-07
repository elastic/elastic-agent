package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
)

func NewMockServer(t *testing.T, host string, called *bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		*called = true
		resp := elasticdiagnostics.Response{
			GlobalDiagnostics: []*proto.ActionDiagnosticUnitResult{
				{
					Description: "Mock Global Diagnostic",
					Filename:    "mock_global.txt",
					ContentType: "text/plain",
					Content:     []byte("This is a mock global diagnostic content"),
				},
			},
		}
		err := json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	l, err := ipc.CreateListener(logger.NewWithoutConfig(""), host)
	require.NoError(t, err)
	server := &http.Server{Handler: mux} //nolint:gosec // This is a test
	go func() {
		err := server.Serve(l)
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()
	return server
}
