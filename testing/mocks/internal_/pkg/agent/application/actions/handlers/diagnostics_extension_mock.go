package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ipc"
	"github.com/stretchr/testify/require"
)

func NewMockServer(t *testing.T, host string, called *bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		*called = true
		err := json.NewEncoder(w).Encode(elasticdiagnostics.Response{})
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})

	l, err := ipc.CreateListener(logger.NewWithoutConfig(""), host)
	require.NoError(t, err)
	server := &http.Server{Handler: mux}
	go func() {
		err := server.Serve(l)
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()
	return server
}
