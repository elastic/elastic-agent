// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//nolint:dupl // tests are not the same, just equivalent
package capabilities

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestLoadCapabilities(t *testing.T) {
	testCases := []string{
		"filter_metrics",
		"allow_metrics",
		"deny_logs",
		"no_caps",
	}

	l, _ := logger.New("test", false)

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			filename := filepath.Join("testdata", fmt.Sprintf("%s-capabilities.yml", tc))
			caps, err := Load(filename, l)
			assert.NoError(t, err)
			assert.NotNil(t, caps)

			cfg, configCloser := getConfigWithCloser(t, filepath.Join("testdata", fmt.Sprintf("%s-config.yml", tc)))
			defer configCloser.Close()

			mm, err := cfg.ToMapStr()
			assert.NoError(t, err)
			assert.NotNil(t, mm)

			out, err := caps.Apply(mm)
			assert.NoError(t, err, "should not be failing")
			assert.NotEqual(t, ErrBlocked, err, "should not be blocking")

			resultConfig, ok := out.(map[string]interface{})
			assert.True(t, ok)

			expectedConfig, resultCloser := getConfigWithCloser(t, filepath.Join("testdata", fmt.Sprintf("%s-result.yml", tc)))
			defer resultCloser.Close()

			expectedMap, err := expectedConfig.ToMapStr()
			assert.NoError(t, err)

			fixInputsType(expectedMap)
			fixInputsType(resultConfig)

			if !assert.True(t, cmp.Equal(expectedMap, resultConfig)) {
				diff := cmp.Diff(expectedMap, resultConfig)
				if diff != "" {
					t.Errorf("%s mismatch (-want +got):\n%s", tc, diff)
				}
			}
		})
	}
}

func TestInvalidLoadCapabilities(t *testing.T) {
	testCases := []string{
		"invalid",
		"invalid_output",
	}

	l, _ := logger.New("test", false)

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			filename := filepath.Join("testdata", fmt.Sprintf("%s-capabilities.yml", tc))
			caps, err := Load(filename, l)
			assert.NoError(t, err)
			assert.NotNil(t, caps)

			cfg, configCloser := getConfigWithCloser(t, filepath.Join("testdata", fmt.Sprintf("%s-config.yml", tc)))
			defer configCloser.Close()

			mm, err := cfg.ToMapStr()
			assert.NoError(t, err)
			assert.NotNil(t, mm)

			_, err = caps.Apply(mm)
			assert.Error(t, err, "should be failing")
			assert.NotEqual(t, ErrBlocked, err, "should not be blocking")
		})
	}
}

func getConfigWithCloser(t *testing.T, cfgFile string) (*config.Config, io.Closer) {
	configFile, err := os.Open(cfgFile)
	require.NoError(t, err)

	cfg, err := config.NewConfigFrom(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	return cfg, configFile
}

func getConfig() map[string]string {
	return map[string]string{
		"filter": "f_val",
		"key":    "val",
	}
}
