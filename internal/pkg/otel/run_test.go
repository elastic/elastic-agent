// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsOtelConfig(t *testing.T) {
	testCases := []struct {
		name           string
		path           string
		expectedResult bool
	}{
		// otel name based
		{"named otel.yml", filepath.Join("testdata", "otel", "otel.yml"), true},
		{"named otel.yaml", filepath.Join("testdata", "otel", "otel.yaml"), true},
		{"named otlp.yml", filepath.Join("testdata", "otel", "otlp.yml"), true},
		{"named otelcol.yml", filepath.Join("testdata", "otel", "otelcol.yml"), true},

		{"otel but wrong extension", filepath.Join("testdata", "otel", "otelcol.json"), false},
		{"wrong filename", filepath.Join("testdata", "otel", "elastic-agent.yml"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := IsOtelConfig(context.TODO(), tc.path)
			require.Equal(t, tc.expectedResult, res)
		})
	}
}
