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
	"testing"
	"time"

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

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return client.Dialer(ctx, config.Endpoint)
		},
	}
	client := &http.Client{Transport: tr}

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		req, err := http.NewRequest(http.MethodGet, "http://localhost/diagnostics", nil)
		require.NoError(collect, err)
		resp, err := client.Do(req.WithContext(context.Background()))
		require.NoError(collect, err)
		require.Equal(collect, http.StatusOK, resp.StatusCode)

		b, err := io.ReadAll(resp.Body)
		require.NoError(collect, err)
		res := Response{}

		// test that the response can be unmarshalled
		require.NoErrorf(collect, json.Unmarshal(b, &res), "failed to unmarshal response: %s", string(b))

		require.NoError(collect, resp.Body.Close())
	}, 5*time.Second, 100*time.Millisecond, "extension did not start in time")
}
