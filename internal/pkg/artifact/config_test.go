// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package artifact

import (
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/stretchr/testify/require"
)

func TestReload(t *testing.T) {
	cfg := DefaultConfig()
	l, _ := logger.NewTesting("t")
	reloader := NewReloader(cfg, l)

	input := `agent.download:
  sourceURI: "testing.uri"
  target_directory: "a/b/c"
  install_path: "i/p"
  drop_path: "d/p"
  ssl.enabled: true
  proxy_disable: true
`

	c, err := config.NewConfigFrom(input)
	require.NoError(t, err)

	require.NoError(t, reloader.Reload(c))

	require.Equal(t, "testing.uri", cfg.SourceURI)
	require.Equal(t, "a/b/c", cfg.TargetDirectory)
	require.NotNil(t, cfg.TLS)
	require.Equal(t, true, *cfg.TLS.Enabled)
	require.NotNil(t, cfg.Proxy)
	require.Equal(t, true, cfg.Proxy.Disable)
}
