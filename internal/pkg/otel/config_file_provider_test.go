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

func TestContentFileProviderOutput(t *testing.T) {
	testCases := []struct {
		name            string
		configFile      string
		expectedOutputs []string
	}{
		{"default", "otel.yml", []string{"stdout"}},
		{"stderr", "otlp.yml", []string{"stderr"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cp := NewFileProviderWithDefaults()
			confMap, err := cp.Retrieve(context.TODO(), "file:"+filepath.Join(".", "testdata", tc.configFile), nil)
			require.NoError(t, err)

			conf, err := confMap.AsConf()
			require.NoError(t, err)
			val := conf.Get("service::telemetry::logs::output_paths")
			require.NotNil(t, val)

			valStrArray, ok := val.([]string)
			require.True(t, ok)
			require.EqualValues(t, tc.expectedOutputs, valStrArray)
		})
	}
}
