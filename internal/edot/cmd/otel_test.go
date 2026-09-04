// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/libbeat/beat"

	"github.com/elastic/elastic-agent/internal/pkg/util"
)

func TestPrepareCollectorSettings(t *testing.T) {
	t.Run("returns valid settings in supervised mode", func(t *testing.T) {
		// mock stdin with a basic OTEL config if needed
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()

		r, w, err := os.Pipe()
		require.NoError(t, err, "failed to create pipe")
		_, err = w.WriteString(`receivers: { otlp: {} }`)
		require.NoError(t, err, "failed to write to pipe")
		require.NoError(t, w.Close(), "failed to close pipe")
		os.Stdin = r

		settings, err := prepareCollectorSettings(nil, true, "info", nil)
		require.NoError(t, err, "failed to prepare collector settings")
		require.NotNil(t, settings, "settings should not be nil")
		require.NotNil(t, settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs, "URIs should not be nil")
		require.NotNil(t, settings.otelSettings.LoggingOptions, "loggingOptions should not be nil for supervised mode")
	})

	t.Run("returns valid settings in standalone mode", func(t *testing.T) {
		settings, err := prepareCollectorSettings([]string{"fake-config.yaml"}, false, "info", nil)
		require.NoError(t, err, "failed to prepare collector settings")
		require.NotNil(t, settings, "settings should not be nil")
		require.Contains(t, settings.otelSettings.ConfigProviderSettings.ResolverSettings.URIs, "fake-config.yaml", "fake-config.yaml not found in the URIS of ConfigProviderSettings")
	})

	t.Run("fails when supervised mode has invalid config from stdin", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		r, w, err := os.Pipe()
		require.NoError(t, err, "failed to create pipe")
		_, err = w.WriteString(`receivers { otlp: {} }`) // invalid yaml
		require.NoError(t, err, "failed to write to pipe")
		require.NoError(t, w.Close(), "failed to close pipe")
		os.Stdin = r

		settings, err := prepareCollectorSettings(nil, true, "info", nil)
		require.Error(t, err)
		require.Nil(t, settings.otelSettings)
	})

	t.Run("doesn't fail when unsupervised mode has invalid config from stdin", func(t *testing.T) {
		oldStdin := os.Stdin
		defer func() { os.Stdin = oldStdin }()
		r, w, err := os.Pipe()
		require.NoError(t, err, "failed to create pipe")
		_, err = w.WriteString(`receivers { otlp: {} }`)
		require.NoError(t, err, "failed to write to pipe")
		require.NoError(t, w.Close(), "failed to close pipe")
		os.Stdin = r

		settings, err := prepareCollectorSettings(nil, false, "info", nil)
		require.NoError(t, err)
		require.NotNil(t, settings)
	})
}

// TestInitBeatHostnameFromEnv tests must not run in parallel: they share the
// process-wide Beat hostname override.
func TestInitBeatHostnameFromEnv(t *testing.T) {
	reset := func() { beat.SetHostnameOverride("") }

	t.Run("plain_value", func(t *testing.T) {
		t.Cleanup(reset)
		t.Setenv(util.EnvHostName, "custom-node")
		initBeatHostnameFromEnv()
		assert.Equal(t, "custom-node", beat.GetHostnameOverride())
	})

	t.Run("whitespace_trimmed", func(t *testing.T) {
		t.Cleanup(reset)
		t.Setenv(util.EnvHostName, "  custom-node  ")
		initBeatHostnameFromEnv()
		assert.Equal(t, "custom-node", beat.GetHostnameOverride())
	})

	t.Run("whitespace_only_clears_stale_override", func(t *testing.T) {
		t.Cleanup(reset)
		beat.SetHostnameOverride("stale-node")
		t.Setenv(util.EnvHostName, "   ")
		initBeatHostnameFromEnv()
		assert.Equal(t, "", beat.GetHostnameOverride())
	})

	t.Run("unset_env_clears_stale_override", func(t *testing.T) {
		t.Cleanup(reset)
		t.Setenv(util.EnvHostName, "")
		beat.SetHostnameOverride("stale-node")
		initBeatHostnameFromEnv()
		assert.Equal(t, "", beat.GetHostnameOverride())
	})
}
