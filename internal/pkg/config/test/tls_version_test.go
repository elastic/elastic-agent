// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestTLSVersionsDefault(t *testing.T) {
	l := newLoader(t, filepath.Join("..", "testdata"))
	c, err := l.Load([]string{filepath.Join("..", "testdata", "tls.yml")})
	require.NoError(t, err)

	agentCfg, err := configuration.NewFromConfig(c)
	require.NoError(t, err)

	common, err := tlscommon.LoadTLSConfig(agentCfg.Fleet.Client.Transport.TLS)
	require.NoError(t, err)
	cfg := common.ToConfig()
	assert.Equal(t, uint16(tls.VersionTLS11), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MaxVersion)
}

func TestTLSVersions10(t *testing.T) {
	l := newLoader(t, filepath.Join("..", "testdata"))
	c, err := l.Load([]string{filepath.Join("..", "testdata", "tls10.yml")})
	require.NoError(t, err)

	agentCfg, err := configuration.NewFromConfig(c)
	require.NoError(t, err)

	common, err := tlscommon.LoadTLSConfig(agentCfg.Fleet.Client.Transport.TLS)
	require.NoError(t, err)
	cfg := common.ToConfig()
	assert.Equal(t, uint16(tls.VersionTLS10), cfg.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS10), cfg.MaxVersion)
}

func newLoader(t *testing.T, folder string) *config.Loader {
	t.Helper()
	log, err := logger.New("config_test", true)
	require.NoError(t, err)
	return config.NewLoader(log, folder)
}
