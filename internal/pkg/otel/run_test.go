// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"
	"path/filepath"
	"sync"
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
			configFiles := []string{"file:" + filepath.Join(".", "testdata", tc.configFile)}
			settings, err := newSettings("test", configFiles)
			require.NoError(t, err)

			collector, err := otelcol.NewCollector(*settings)
			require.NoError(t, err)
			require.NotNil(t, collector)

			wg := startCollector(context.Background(), t, collector, tc.expectedErrorMessage)

			if tc.expectedErrorMessage == "" {
				assert.Eventually(t, func() bool {
					return otelcol.StateRunning == collector.GetState()
				}, 2*time.Second, 200*time.Millisecond)
			}
			collector.Shutdown()
			wg.Wait()
			assert.Equal(t, otelcol.StateClosed, collector.GetState())
		})
	}
}

func startCollector(ctx context.Context, t *testing.T, col *otelcol.Collector, expectedErrorMessage string) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := col.Run(ctx)
		if expectedErrorMessage == "" {
			require.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), expectedErrorMessage)
		}
	}()
	return wg
}
