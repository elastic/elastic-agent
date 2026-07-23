// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/go-ucfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestLoadBaseConfig(t *testing.T) {
	origConfig := paths.Config()
	t.Cleanup(func() { paths.SetConfig(origConfig) })
	paths.SetConfig(t.TempDir())

	require.NoError(t, os.WriteFile(paths.ConfigFile(), []byte(`
fleet:
  enabled: true
agent:
  logging:
    level: debug
`), 0o644))
	require.NoError(t, os.WriteFile(paths.AgentConfigFile(), []byte("invalid persisted Fleet config"), 0o644))

	cfg, err := LoadBaseConfig(func(cfg *config.Config) error {
		return cfg.Merge(map[string]any{
			"agent.logging.to_files":  false,
			"agent.logging.to_stderr": true,
		})
	})
	require.NoError(t, err)

	// Base settings include local configuration and overrides but not Fleet values.
	assert.True(t, cfg.Fleet.Enabled)
	assert.Empty(t, cfg.Fleet.AccessAPIKey)
	assert.Equal(t, logp.DebugLevel, cfg.Settings.LoggingConfig.Level)
	assert.False(t, cfg.Settings.LoggingConfig.ToFiles)
	assert.True(t, cfg.Settings.LoggingConfig.ToStderr)
	assert.NotNil(t, cfg.Settings.EventLoggingConfig)

	// Runtime path values are injected into the base configuration.
	logsPath, err := cfg.UCfg.Agent.String("path.logs", -1, ucfg.PathSep("."))
	require.NoError(t, err)
	assert.Equal(t, paths.Logs(), logsPath)
}

func TestLoadConfigFromBase(t *testing.T) {
	validFleetEnc := `fleet:
  enabled: true
  kibana:
    host: demo
  access_api_key: "123"
agent:
  grpc:
    port: 6790`

	tests := []struct {
		name     string
		baseCfg  string
		fleetEnc string
		assert   func(t *testing.T, cfg *Configuration)
	}{
		{
			name:     "fleet enabled, fleet.enc merged",
			baseCfg:  "fleet:\n  enabled: true\n",
			fleetEnc: validFleetEnc,
			assert: func(t *testing.T, cfg *Configuration) {
				assert.True(t, cfg.Fleet.Enabled)
				assert.Equal(t, "123", cfg.Fleet.AccessAPIKey)
				assert.Equal(t, uint16(6790), cfg.Settings.GRPC.Port)
			},
		},
		{
			name:     "standalone ignores fleet.enc",
			baseCfg:  "fleet:\n  enabled: false\n",
			fleetEnc: validFleetEnc,
			assert: func(t *testing.T, cfg *Configuration) {
				assert.False(t, cfg.Fleet.Enabled)
				assert.Empty(t, cfg.Fleet.AccessAPIKey)
			},
		},
		{
			name: "overlapping agent.logging.level",
			baseCfg: `fleet:
  enabled: true
agent:
  logging:
    level: info
`,
			fleetEnc: `fleet:
  enabled: true
  kibana:
    host: demo
  access_api_key: "123"
agent:
  logging:
    level: debug`,
			assert: func(t *testing.T, cfg *Configuration) {
				assert.True(t, cfg.Fleet.Enabled)
				assert.Equal(t, logp.DebugLevel, cfg.Settings.LoggingConfig.Level)
			},
		},
		{
			name: "fleet overrides baseline agent output",
			baseCfg: `fleet:
  enabled: true
agent:
  logging:
    to_files: false
    to_stderr: true
`,
			fleetEnc: `fleet:
  enabled: true
agent:
  logging:
    to_files: true
    to_stderr: false`,
			assert: func(t *testing.T, cfg *Configuration) {
				assert.True(t, cfg.Settings.LoggingConfig.ToFiles)
				assert.False(t, cfg.Settings.LoggingConfig.ToStderr)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origConfig := paths.Config()
			t.Cleanup(func() { paths.SetConfig(origConfig) })
			paths.SetConfig(t.TempDir())
			testutils.InitStorage(t)
			require.NoError(t, os.WriteFile(paths.ConfigFile(), []byte(tt.baseCfg), 0o644))

			store, err := storage.NewEncryptedDiskStore(t.Context(), paths.AgentConfigFile())
			require.NoError(t, err)
			require.NoError(t, store.Save(strings.NewReader(tt.fleetEnc)))

			base, err := LoadBaseConfig(nil)
			require.NoError(t, err)
			cfg, err := LoadConfigFromBase(t.Context(), base, nil)
			require.NoError(t, err)
			tt.assert(t, cfg)
		})
	}
}

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
