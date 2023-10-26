// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestHost(t *testing.T) {
	testCases := []struct {
		name         string
		config       string
		expectedHost string
	}{
		{"no host", `enabled: true
logs: true
metrics: true
http:
  enabled: true`, defaultHost},
		{"empty host", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: ""`, defaultHost},
		{"default", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: localhost`, defaultHost},
		{"custom host", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: custom`, "custom"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := config.NewConfigFrom(tc.config)
			require.NoError(t, err, "failed to create config")

			cfg := DefaultConfig()
			c.Unpack(&cfg)
			require.NoError(t, err, "failed to unpack config")

			require.Equal(t, tc.expectedHost, cfg.HTTP.Host)
		})
	}
}

func TestAPMConfig(t *testing.T) {
	tcs := map[string]struct {
		in  map[string]interface{}
		out APMConfig
	}{
		"default": {
			in:  map[string]interface{}{},
			out: defaultAPMConfig(),
		},
		"custom": {
			in: map[string]interface{}{
				"traces": true,
				"apm": map[string]interface{}{
					"api_key":     "abc123",
					"environment": "production",
					"hosts":       []string{"https://abc.123.com"},
					"tls": map[string]interface{}{
						"skip_verify":        true,
						"server_certificate": "server_cert",
						"server_ca":          "server_ca",
					},
				},
			},
			out: APMConfig{
				APIKey:      "abc123",
				Environment: "production",
				Hosts:       []string{"https://abc.123.com"},
				TLS: APMTLS{
					SkipVerify:        true,
					ServerCertificate: "server_cert",
					ServerCA:          "server_ca",
				},
			},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			in, err := config.NewConfigFrom(tc.in)
			require.NoError(t, err)

			cfg := DefaultConfig()
			require.NoError(t, in.Unpack(cfg))
			require.NotNil(t, cfg)

			assert.DeepEqual(t, tc.out, cfg.APM)
		})
	}
}
