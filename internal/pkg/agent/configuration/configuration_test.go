// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/component"
)

// TestNewFromConfig_RuntimeConfigFromFile loads a YAML config file that sets
// runtime manager overrides and verifies the RuntimeConfig is unpacked
// correctly. In particular it exercises the BeatRuntimeConfig inline map +
// "default" struct field combination that triggered go-ucfg bug
// https://github.com/elastic/go-ucfg/issues/215 (the "default" value leaked
// into the inline InputType map). Validate contains a workaround that removes
// the spurious key; this test ensures the final state is correct regardless
// of whether the upstream bug is present.
func TestNewFromConfig_RuntimeConfigFromFile(t *testing.T) {
	cfg, err := config.LoadFile(filepath.Join("testdata", "runtime_config.yaml"))
	require.NoError(t, err)

	c, err := NewFromConfig(cfg)
	require.NoError(t, err)

	runtime := c.Settings.Internal.Runtime
	require.NotNil(t, runtime)

	assert.Equal(t, string(component.OtelRuntimeManager), runtime.Default)

	// filebeat: default + one explicit input type override
	assert.Equal(t, "otel", runtime.Filebeat.Default)
	assert.Equal(t, map[string]string{"log/metrics": "process"}, runtime.Filebeat.InputType,
		"InputType must contain only the explicitly configured keys, no spurious 'default' entry")

	// metricbeat: no default override; system/metrics set in the fixture, rest
	// comes from DefaultRuntimeConfig defaults.
	assert.Equal(t, string(component.OtelRuntimeManager), runtime.Metricbeat.Default)
	assert.Equal(t, string(component.OtelRuntimeManager), runtime.Metricbeat.InputType["system/metrics"])
}

// TestNewFromConfig_DynamicInputsConfig verifies that both the legacy scalar form and the
// richer map form of agent.internal.runtime.dynamic_inputs are unpacked correctly through the
// regular configuration loading path.
func TestNewFromConfig_DynamicInputsConfig(t *testing.T) {
	t.Run("legacy scalar form", func(t *testing.T) {
		c, err := NewFromConfig(config.MustNewConfigFrom(`
agent.internal.runtime.dynamic_inputs: process
`))
		require.NoError(t, err)

		dynamicInputs := c.Settings.Internal.Runtime.DynamicInputs
		assert.Equal(t, string(component.ProcessRuntimeManager), dynamicInputs.Default)
		assert.Empty(t, dynamicInputs.StaticVariables)
		assert.Equal(t, component.ProcessRuntimeManager,
			dynamicInputs.RuntimeManagerForDynamicInput("filebeat", "filestream"))
	})

	t.Run("map form", func(t *testing.T) {
		c, err := NewFromConfig(config.MustNewConfigFrom(`
agent:
  internal:
    runtime:
      dynamic_inputs:
        default: process
        filebeat:
          default: process
          filestream: otel
        metricbeat:
          default: otel
        static_variables:
          - local_dynamic.group
          - kubernetes.node
`))
		require.NoError(t, err)

		dynamicInputs := c.Settings.Internal.Runtime.DynamicInputs
		assert.Equal(t, "process", dynamicInputs.Default)
		assert.Equal(t, "process", dynamicInputs.Filebeat.Default)
		assert.Equal(t, map[string]string{"filestream": "otel"}, dynamicInputs.Filebeat.InputType)
		assert.Equal(t, "otel", dynamicInputs.Metricbeat.Default)
		assert.Equal(t, []string{"local_dynamic.group", "kubernetes.node"}, dynamicInputs.StaticVariables)

		// per input type wins over the beat default, which wins over the global default
		assert.Equal(t, component.OtelRuntimeManager,
			dynamicInputs.RuntimeManagerForDynamicInput("filebeat", "filestream"))
		assert.Equal(t, component.ProcessRuntimeManager,
			dynamicInputs.RuntimeManagerForDynamicInput("filebeat", "log"))
		assert.Equal(t, component.OtelRuntimeManager,
			dynamicInputs.RuntimeManagerForDynamicInput("metricbeat", "system/metrics"))
		assert.Equal(t, component.ProcessRuntimeManager,
			dynamicInputs.RuntimeManagerForDynamicInput("packetbeat", "packet"))
	})

	t.Run("unset leaves the feature disabled", func(t *testing.T) {
		c, err := NewFromConfig(config.MustNewConfigFrom(`agent.internal.runtime.default: otel`))
		require.NoError(t, err)

		dynamicInputs := c.Settings.Internal.Runtime.DynamicInputs
		assert.Equal(t, "", dynamicInputs.Default)
		assert.Equal(t, component.RuntimeManager(""),
			dynamicInputs.RuntimeManagerForDynamicInput("filebeat", "filestream"))
	})

	t.Run("invalid runtime manager is rejected", func(t *testing.T) {
		_, err := NewFromConfig(config.MustNewConfigFrom(`
agent.internal.runtime.dynamic_inputs.default: nonsense
`))
		require.Error(t, err)
	})
}

func TestNewConfigReloader_StandaloneConfig(t *testing.T) {
	setupConfigReloaderTest(t)

	writeStartupConfig(t, `
fleet:
  enabled: false
agent:
  logging:
    level: info
`)
	writeFleetConfig(t, "corrupted Fleet data is ignored")

	startupOverride := func(cfg *config.Config) error {
		return cfg.Merge(map[string]any{"agent.logging.level": "debug"})
	}
	reloader, err := NewConfigReloader(t.Context(), startupOverride, nil)
	require.NoError(t, err)

	startup := reloader.StartupConfiguration()
	cfg := reloader.Configuration()

	// Without Fleet values, startup and applied configurations are equal.
	assert.Equal(t, startup.Fleet, cfg.Fleet)
	assert.Equal(t, startup.Settings, cfg.Settings)

	// The startup override is applied.
	assert.Equal(t, "debug", startup.Settings.LoggingConfig.Level.String())
	assert.Equal(t, "debug", cfg.Settings.LoggingConfig.Level.String())
}

func TestNewConfigReloader_FleetManagedConfig(t *testing.T) {
	setupConfigReloaderTest(t)

	writeStartupConfig(t, `
fleet:
  enabled: true
agent:
  grpc:
    port: 6788
  logging:
    to_stderr: true
`)
	writeFleetConfig(t, `
fleet:
  enabled: true
  access_api_key: "fleet-key"
agent:
  grpc:
    port: 6789
  logging:
    level: info
`)

	startupOverride := func(cfg *config.Config) error {
		return cfg.Merge(map[string]any{"agent.logging.level": "debug"})
	}
	configOverride := func(cfg *config.Config) error {
		return cfg.Merge(map[string]any{"agent.grpc.port": 6790})
	}
	reloader, err := NewConfigReloader(t.Context(), startupOverride, configOverride)
	require.NoError(t, err)

	startup := reloader.StartupConfiguration()
	cfg := reloader.Configuration()

	// Startup fields are preserved.
	assert.True(t, startup.Settings.LoggingConfig.ToStderr)
	assert.True(t, cfg.Settings.LoggingConfig.ToStderr)

	// Fleet fields are preserved.
	assert.Equal(t, "fleet-key", cfg.Fleet.AccessAPIKey)

	// Fleet overrides the startup logging level.
	assert.Equal(t, "debug", startup.Settings.LoggingConfig.Level.String())
	assert.Equal(t, "info", cfg.Settings.LoggingConfig.Level.String())

	// The config override overrides the startup gRPC port.
	assert.Equal(t, uint16(6788), startup.Settings.GRPC.Port)
	assert.Equal(t, uint16(6790), cfg.Settings.GRPC.Port)
}

func TestConfigReloader_ReloadsAfterEnrollment(t *testing.T) {
	setupConfigReloaderTest(t)

	writeStartupConfig(t, `
fleet:
  enabled: false
`)

	reloader, err := NewConfigReloader(t.Context(), nil, nil)
	require.NoError(t, err)

	// The reloader starts in standalone mode.
	cfg := reloader.Configuration()
	assert.False(t, cfg.Fleet.Enabled)

	// A Fleet configuration enables managed mode on reload.
	writeStartupConfig(t, `
fleet:
  enabled: true
`)
	writeFleetConfig(t, `
fleet:
  enabled: true
  access_api_key: "fleet-key"
`)
	err = reloader.Reload(t.Context())
	require.NoError(t, err)
	cfg = reloader.Configuration()
	assert.True(t, cfg.Fleet.Enabled)
	assert.Equal(t, "fleet-key", cfg.Fleet.AccessAPIKey)

	// Disabling Fleet returns the reloader to standalone mode.
	writeStartupConfig(t, `
fleet:
  enabled: false
`)
	require.NoError(t, reloader.Reload(t.Context()))
	cfg = reloader.Configuration()
	assert.False(t, cfg.Fleet.Enabled)
	assert.Empty(t, cfg.Fleet.AccessAPIKey)
}

func setupConfigReloaderTest(t *testing.T) {
	t.Helper()
	origConfig := paths.Config()
	t.Cleanup(func() { paths.SetConfig(origConfig) })
	paths.SetConfig(t.TempDir())
	testutils.InitStorage(t)
}

func writeStartupConfig(t *testing.T, startupConfig string) {
	t.Helper()
	err := os.WriteFile(paths.ConfigFile(), []byte(startupConfig), 0o644)
	require.NoError(t, err)
}

func writeFleetConfig(t *testing.T, fleetConfig string) {
	t.Helper()
	store, err := storage.NewEncryptedDiskStore(t.Context(), paths.AgentConfigFile())
	require.NoError(t, err)
	err = store.Save(strings.NewReader(fleetConfig))
	require.NoError(t, err)
}
