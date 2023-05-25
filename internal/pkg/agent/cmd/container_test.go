// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestEnvWithDefault(t *testing.T) {
	def := "default"
	key1 := "ENV_WITH_DEFAULT_1"
	key2 := "ENV_WITH_DEFAULT_2"

	res := envWithDefault(def, key1, key2)

	require.Equal(t, def, res)

	err := os.Setenv(key1, "key1")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	err = os.Setenv(key2, "key2")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res2 := envWithDefault(def, key1, key2)
	require.Equal(t, "key1", res2)
}

func TestEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL"

	err := os.Setenv(key, "true")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res := envBool(key)
	require.True(t, res)
}

func TestEnvTimeout(t *testing.T) {
	key := "TEST_ENV_TIMEOUT"

	err := os.Setenv(key, "10s")
	if err != nil {
		t.Skipf("could not export env var: %s", err)
	}

	res := envTimeout(key)
	require.Equal(t, time.Second*10, res)
}

func TestContainerTestPaths(t *testing.T) {
	cases := map[string]struct {
		config   string
		expected containerPaths
	}{
		"only_state_path": {
			config: `state_path: /foo/bar/state`,
			expected: containerPaths{
				StatePath:  "/foo/bar/state",
				ConfigPath: "",
				LogsPath:   "",
			},
		},
		"only_config_path": {
			config: `config_path: /foo/bar/config`,
			expected: containerPaths{
				StatePath:  "",
				ConfigPath: "/foo/bar/config",
				LogsPath:   "",
			},
		},
		"only_logs_path": {
			config: `logs_path: /foo/bar/logs`,
			expected: containerPaths{
				StatePath:  "",
				ConfigPath: "",
				LogsPath:   "/foo/bar/logs",
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(c.config)
			require.NoError(t, err)

			var paths containerPaths
			err = cfg.Unpack(&paths)
			require.NoError(t, err)

			require.Equal(t, c.expected, paths)
		})
	}
}
