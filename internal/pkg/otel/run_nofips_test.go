// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package otel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"
)

func TestStartCollector(t *testing.T) {
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
			expectedErrorMessage: `error decoding 'extensions': unknown type: "zpages"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.configFile, func(t *testing.T) {
			configFiles := getConfigFiles(tc.configFile)
			settings := NewSettings("test", configFiles)

			collector, err := otelcol.NewCollector(*settings)
			require.NoError(t, err)
			require.NotNil(t, collector)

			wg := startCollector(context.Background(), t, collector, tc.expectedErrorMessage)

			if tc.expectedErrorMessage == "" {
				assert.Eventually(t, func() bool {
					return otelcol.StateRunning == collector.GetState()
				}, 10*time.Second, 200*time.Millisecond)
			}
			collector.Shutdown()
			wg.Wait()
			assert.Equal(t, otelcol.StateClosed, collector.GetState())
		})
	}
}
