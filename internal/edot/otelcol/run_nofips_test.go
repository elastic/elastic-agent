// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package otelcol

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/edot/otelcol/components"
)

func TestStartCollector(t *testing.T) {
	// The sigv4auth extension resolves AWS credentials when its config is validated.
	// Provide static ones so the default credential chain doesn't fall back to EC2 IMDS.
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")

	testCases := []struct {
		configFile           string
		expectedErrorMessage string
	}{
		{
			configFile:           "all-components.yml",
			expectedErrorMessage: "", // empty string means no error is expected
		},
		{
			configFile:           "nonexistent-component.yml",
			expectedErrorMessage: `'extensions' unknown type: "zpages"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.configFile, func(t *testing.T) {
			configFiles := getConfigFiles(tc.configFile)
			settings := NewSettings("test", configFiles, WithComponents(components.Default()))

			collector, err := otelcol.NewCollector(*settings)
			require.NoError(t, err)
			require.NotNil(t, collector)

			wg := startCollector(context.Background(), t, collector, tc.expectedErrorMessage)

			if tc.expectedErrorMessage == "" {
				// Starting all components can take well over 10s on slow CI runners: e.g. every
				// Prometheus scrape manager resolves the host FQDN on start, which blocks for
				// several seconds where hostname DNS lookups time out (macOS GitHub runners).
				assert.Eventually(t, func() bool {
					return otelcol.StateRunning == collector.GetState()
				}, 30*time.Second, 200*time.Millisecond)
				collector.Shutdown()
			}
			wg.Wait()
			assert.Equal(t, otelcol.StateClosed, collector.GetState())
		})
	}
}
