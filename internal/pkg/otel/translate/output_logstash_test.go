// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func TestLogStashToExporter(t *testing.T) {
	input := `
hosts: localhost:5044
worker: 3
loadbalance: true
proxy_url: socks5://user:password@socks5-proxy:2233
`

	expectedOTeMap := map[string]any{
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
	}

	cfg, err := config.NewConfigFrom(input)
	if err != nil {
		t.Fatalf("error creating config: %v", err)
	}

	logger := logp.NewLogger("test")
	otelCfg, err := LogstashToOTelConfig(cfg, logger)
	if err != nil {
		t.Fatalf("error translating logstash output to logstash exporter config: %v", err)
	}
	require.Equal(t, expectedOTeMap, otelCfg)
}
