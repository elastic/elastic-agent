// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOtelConfig(t *testing.T) {
	testCases := []struct {
		name           string
		path           string
		expectedResult bool
		expectedErr    error
	}{
		// otel name based
		{"named otel.yml", filepath.Join("testdata", "otel", "otel.yml"), true, nil},
		{"named otel.yaml", filepath.Join("testdata", "otel", "otel.yaml"), true, nil},
		{"named otlp.yml", filepath.Join("testdata", "otel", "otlp.yml"), true, nil},
		{"named otelcol.yml", filepath.Join("testdata", "otel", "otelcol.yml"), true, nil},

		// content based
		{"otel content - elastic-agent.yml", filepath.Join("testdata", "otel", "elastic-agent.yml"), true, nil},
		{"otel content - config.yml", filepath.Join("testdata", "otel", "config.yml"), true, nil},
		{"agent content - agent.yml", filepath.Join("testdata", "agent", "agent.yml"), false, nil},
		{"agent content - elastic-agent.yml", filepath.Join("testdata", "agent", "elastic-agent.yml"), false, nil},
		{"agent content - policy.yml", filepath.Join("testdata", "agent", "policy.yml"), false, nil},

		// error handling
		{"note existing file", filepath.Join("testdata", "invalid.yml"), false, os.ErrNotExist},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := IsOtelConfig(context.TODO(), tc.path)
			require.Equal(t, tc.expectedResult, res)
			require.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
