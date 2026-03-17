// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
)

func TestLogStashToExporter(t *testing.T) {

	testCases := []struct {
		name        string
		input       string
		expectedMap map[string]any
	}{{
		name: "basic translation logic",
		input: `
hosts: 
- localhost:5044
worker: 3
loadbalance: true
proxy_url: socks5://user:password@socks5-proxy:2233
`,
		expectedMap: map[string]any{
			"hosts":       []any{"localhost:5044"},
			"worker":      uint64(3),
			"loadbalance": true,
			"proxy_url":   "socks5://user:password@socks5-proxy:2233",
			"backoff": map[string]any{
				"init": "1s",
				"max":  "1m0s",
			},
			"bulk_max_size":            uint64(2048),
			"compression_level":        uint64(3),
			"escape_html":              false,
			"index":                    "",
			"max_retries":              uint64(3),
			"pipelining":               uint64(2),
			"proxy_use_local_resolver": false,
			"slow_start":               false,
			"timeout":                  "30s",
			"ttl":                      "0s",
			"workers":                  int64(0),
		},
	},
		{
			name: "when host is a string and ssl is configured",
			input: `
hosts: 
- localhost:5044
worker: 3
ssl.enabled: true
ssl.certificate_authorities: "/not/a/real/path/ca.pem"
ssl.supported_protocols: "TLSv1.3"
ssl.curve_types: "P-256"
`,
			expectedMap: map[string]any{
				"hosts":       []any{"localhost:5044"},
				"worker":      uint64(3),
				"loadbalance": false,
				"proxy_url":   "",
				"backoff": map[string]any{
					"init": "1s",
					"max":  "1m0s",
				},
				"bulk_max_size":            uint64(2048),
				"compression_level":        uint64(3),
				"escape_html":              false,
				"index":                    "",
				"max_retries":              uint64(3),
				"pipelining":               uint64(2),
				"proxy_use_local_resolver": false,
				"slow_start":               false,
				"timeout":                  "30s",
				"ttl":                      "0s",
				"workers":                  int64(0),
				"ssl": map[string]any{
					"enabled":                 true,
					"certificate":             "",
					"key":                     "",
					"key_passphrase":          "",
					"key_passphrase_path":     "",
					"ca_trusted_fingerprint":  "",
					"ca_sha256":               []any{},
					"supported_protocols":     []any{uint64(772)},
					"certificate_authorities": []any{"/not/a/real/path/ca.pem"},
					"renegotiation":           int64(0),
					"cipher_suites":           []any{},
					"verification_mode":       uint64(0),
					"curve_types":             []any{uint64(23)},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(test.input)
			if err != nil {
				t.Fatalf("error creating config: %v", err)
			}

			logger := logptest.NewTestingLogger(t, "test")
			otelCfg, err := LogstashToOTelConfig(cfg, logger)
			if err != nil {
				t.Fatalf("error translating logstash output to logstash exporter config: %v", err)
			}
			require.Equal(t, test.expectedMap, otelCfg)
		})
	}

}
