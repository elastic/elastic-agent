package translate

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/require"
)

func TestLogStashToExporter(t *testing.T) {
	input := `
hosts: localhost:5044
worker: 3
loadbalance: true
proxy_url: socks5://user:password@socks5-proxy:2233
`

	expectedOTeMap := map[string]any{
		"hosts":       "localhost:5044",
		"worker":      uint64(3),
		"loadbalance": true,
		"proxy_url":   "socks5://user:password@socks5-proxy:2233",
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
