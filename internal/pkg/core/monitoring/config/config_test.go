// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestIsSetLogic(t *testing.T) {
	testCases := []struct {
		name            string
		config          string
		startingCfg     *MonitoringConfig
		expectedEnabled bool
		expectedIsSet   bool
	}{
		{
			"explicitly-disabled",
			`enabled: true
logs: true
metrics: true
http:
  enabled: false`,
			DefaultConfig(),
			false, true,
		},
		{
			"explicitly-enabled",
			`enabled: true
logs: true
metrics: true
http:
  enabled: true`,
			DefaultConfig(),
			true, true,
		},
		{
			"not-set",
			`enabled: true
logs: true
metrics: true`,
			DefaultConfig(),
			false, false,
		},
		{
			"not-set-default-enabled",
			`enabled: true
logs: true
metrics: true
http:
  port: 1234`,
			&MonitoringConfig{
				Enabled:     true,
				HTTP:        &MonitoringHTTPConfig{Enabled: true, Host: DefaultHost, Port: defaultPort},
				Namespace:   defaultNamespace,
				APM:         defaultAPMConfig(),
				Diagnostics: defaultDiagnostics(),
			},
			true, false,
		},
		{
			"no-http-field-default-enabled",
			`enabled: true
logs: true
metrics: true`,
			&MonitoringConfig{
				Enabled:     true,
				HTTP:        &MonitoringHTTPConfig{Enabled: true, Host: DefaultHost, Port: defaultPort},
				Namespace:   defaultNamespace,
				APM:         defaultAPMConfig(),
				Diagnostics: defaultDiagnostics(),
			},
			true, false,
		},
		{
			"empty-cfg",
			``,
			&MonitoringConfig{
				Enabled:     true,
				HTTP:        &MonitoringHTTPConfig{Enabled: true, Host: DefaultHost, Port: defaultPort},
				Namespace:   defaultNamespace,
				APM:         defaultAPMConfig(),
				Diagnostics: defaultDiagnostics(),
			},
			true, false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			c, err := config.NewConfigFrom(testCase.config)
			require.NoError(t, err, "failed to create config")

			cfg := testCase.startingCfg
			err = c.Unpack(&cfg)
			require.NoError(t, err, "failed to unpack config")

			assert.Equal(t, testCase.expectedEnabled, cfg.HTTP.Enabled, "enabled incorrect")
			assert.Equal(t, testCase.expectedIsSet, cfg.HTTP.EnabledIsSet, "IsSet incorrect")
		})
	}
}

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
  enabled: true`, DefaultHost},
		{"empty host", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: ""`, DefaultHost},
		{"whitespace host", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: "   "`, DefaultHost},
		{"default", `enabled: true
logs: true
metrics: true
http:
  enabled: true
  host: localhost`, DefaultHost},
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
			err = c.Unpack(&cfg)
			require.NoError(t, err, "failed to unpack config")

			require.Equal(t, tc.expectedHost, cfg.HTTP.Host)
		})
	}
}

func TestAPMConfig(t *testing.T) {

	tenPercentSamplingRate := float32(0.1)

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
		"sampling_rate 10%": {
			in: map[string]interface{}{
				"traces": true,
				"apm": map[string]interface{}{
					"api_key":       "abc123",
					"environment":   "production",
					"hosts":         []string{"https://abc.123.com"},
					"sampling_rate": &tenPercentSamplingRate,
				},
			},
			out: APMConfig{
				APIKey:       "abc123",
				Environment:  "production",
				Hosts:        []string{"https://abc.123.com"},
				TLS:          APMTLS{},
				SamplingRate: &tenPercentSamplingRate,
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

			assert.Equal(t, tc.out, cfg.APM)
		})
	}
}
