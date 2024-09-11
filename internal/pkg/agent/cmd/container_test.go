// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
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

	t.Setenv(key1, "key1")

	t.Setenv(key2, "key2")

	res2 := envWithDefault(def, key1, key2)
	require.Equal(t, "key1", res2)
}

func TestEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL"

	t.Setenv(key, "true")

	res := envBool(key)
	require.True(t, res)
}

func TestEnvTimeout(t *testing.T) {
	key := "TEST_ENV_TIMEOUT"

	t.Setenv(key, "10s")

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

func TestBuildEnrollArgs(t *testing.T) {
	cases := map[string]struct {
		cfg    setupConfig
		expect []string
		err    error
	}{
		"service token passes": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:         "http://localhost:9200",
						ServiceToken: "token-val",
					},
				},
			},
			expect: []string{"--fleet-server-service-token", "token-val"},
			err:    nil,
		},
		"service token path passes": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:             "http://localhost:9200",
						ServiceTokenPath: "/path/to/token",
					},
				},
			},
			expect: []string{"--fleet-server-service-token-path", "/path/to/token"},
			err:    nil,
		},
		"service token path preferred": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:             "http://localhost:9200",
						ServiceTokenPath: "/path/to/token",
						ServiceToken:     "token-val",
					},
				},
			},
			expect: []string{"--fleet-server-service-token-path", "/path/to/token"},
			err:    nil,
		},
		"mTLS flags": {
			cfg: setupConfig{
				Fleet: fleetConfig{
					Cert:    "/path/to/agent.crt",
					CertKey: "/path/to/agent.key",
				},
				FleetServer: fleetServerConfig{
					Enable:     true,
					ClientAuth: "optional",
					Elasticsearch: elasticsearchConfig{
						Cert:    "/path/to/es.crt",
						CertKey: "/path/to/es.key",
					},
				},
			},
			expect: []string{"--fleet-server-es-cert", "/path/to/es.crt", "--fleet-server-es-cert-key", "/path/to/es.key", "--fleet-server-client-auth", "optional", "--elastic-agent-cert", "/path/to/agent.crt", "--elastic-agent-cert-key", "/path/to/agent.key"},
			err:    nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := buildEnrollArgs(tc.cfg, "", "")
			if tc.err != nil {
				require.EqualError(t, err, tc.err.Error())
			} else {
				require.NoError(t, err)
			}
			for _, arg := range tc.expect {
				require.Contains(t, args, arg)
			}
		})
	}
}
