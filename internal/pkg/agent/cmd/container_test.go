// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

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
