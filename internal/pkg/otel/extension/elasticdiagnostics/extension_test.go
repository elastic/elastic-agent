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
