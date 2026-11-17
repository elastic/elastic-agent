// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestLimitsLog(t *testing.T) {
	log, obs := loggertest.New("TestLimitsLog")
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	rollbackSrc := newMockRollbacksSource(t)

	_, _, _, err := New(
		ctx,
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{}, // info.AgentInfo
		nil,               // coordinator.ReExecManager
		nil,               // apm.Tracer
		true,              // testingMode
		time.Millisecond,  // fleetInitTimeout
		true,              // disable monitoring
		nil,
		configuration.DefaultConfiguration(),
		nil,
		rollbackSrc,
	)
	require.NoError(t, err)

	old := limits.LimitsConfig{
		GoMaxProcs: 0,
	}
	new := limits.LimitsConfig{
		GoMaxProcs: 99,
	}

	// apply is also called inside `New`, however there is no log line because the config file
	// does not define `agent.limits.go_max_procs` and the default value does not change.
	// so, no callback, no log line.

	// now we trigger the log line
	err = limits.Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`))
	require.NoError(t, err)

	expLogLine := fmt.Sprintf("agent limits have changed: %+v -> %+v", old, new)
	logs := obs.FilterMessageSnippet(expLogLine)
	require.Equalf(t, 1, logs.Len(), "expected one log message about limits change")
}

func TestInjectOutputOverrides(t *testing.T) {
	scenarios := []struct {
		Name         string
		RawConfig    map[string]any
		ChangeConfig map[string]any
		Result       map[string]any
	}{
		{
			Name: "rawConfig no outputs",
			RawConfig: map[string]any{
				"inputs": []any{},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
		},
		{
			Name: "change config no outputs",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			ChangeConfig: map[string]any{
				"inputs": []any{},
			},
			Result: map[string]any{
				"inputs": []any{},
			},
		},
		{
			Name: "mismatch output",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"elasticsearch": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"elasticsearch": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
		},
		{
			Name: "simple merge",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
		},
		{
			Name: "simple merge array",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-Other-Field": "field-123",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth":    "token-123",
							"X-Other-Field": "field-123",
						},
					},
				},
			},
		},
		{
			Name: "override setting from change",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "token-123",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth": "token-546",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth": "token-546",
						},
					},
				},
			},
		},
		{
			Name: "setting variables are not expanded",
			RawConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "elasticsearch",
						"headers": map[string]any{
							"X-App-Auth": "${filesource.app_token}",
						},
					},
				},
			},
			ChangeConfig: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Other": "${filesource.other_token}",
						},
					},
				},
			},
			Result: map[string]any{
				"outputs": map[string]any{
					"default": map[string]any{
						"type": "kafka",
						"headers": map[string]any{
							"X-App-Auth":  "${filesource.app_token}",
							"X-App-Other": "${filesource.other_token}",
						},
					},
				},
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			log, _ := loggertest.New(t.Name())
			rawConfig := config.MustNewConfigFrom(scenario.RawConfig)
			cc := &mockConfigChange{c: config.MustNewConfigFrom(scenario.ChangeConfig)}
			observed := injectOutputOverrides(log, rawConfig)(cc).Config()
			observedMap, err := observed.ToMapStr()
			require.NoError(t, err)
			assert.Equal(t, scenario.Result, observedMap)
		})
	}
}

func Test_normalizeInstallDescriptorAtStartup(t *testing.T) {

	now := time.Now()
	tomorrow := now.Add(24 * time.Hour)
	yesterday := now.Add(-24 * time.Hour)

	tests := []struct {
		name                    string
		setup                   func(t *testing.T, topDir string) (*upgrade.UpdateMarker, rollbacksSource)
		postNormalizeAssertions func(t *testing.T, topDir string, initialUpdateMarker *upgrade.UpdateMarker)
	}{
		{
			name: "happy path: single install, no rollbacks, no modifications needed",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, rollbacksSource) {
				mockRollbackSource := newMockRollbacksSource(t)
				mockRollbackSource.EXPECT().Get().Return(nil, nil)
				return nil, mockRollbackSource
			},

			postNormalizeAssertions: nil,
		},
		{
			name: "Agent was manually rolled back: rolled back install is removed from the list",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, rollbacksSource) {
				newAgentInstallPath := createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				mockRollbackSource := newMockRollbacksSource(t)
				mockRollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					oldAgentInstallPath: {
						Version:    "1.2.3",
						Hash:       "oldversionhash",
						ValidUntil: tomorrow,
					},
				}, nil)

				updateMarker := &upgrade.UpdateMarker{
					Version:           "4.5.6",
					Hash:              "newversionhash",
					VersionedHome:     newAgentInstallPath,
					UpdatedOn:         now,
					PrevVersion:       "1.2.3",
					PrevHash:          "oldversionhash",
					PrevVersionedHome: oldAgentInstallPath,
					Acked:             false,
					Action:            nil,
					Details: &details.Details{
						TargetVersion: "4.5.6",
						State:         details.StateRollback,
						ActionID:      "",
						Metadata: details.Metadata{
							Reason: details.ReasonManualRollbackPattern,
						},
					},
				}

				// expect code to clear the rollback
				mockRollbackSource.EXPECT().Set(map[string]ttl.TTLMarker{}).Return(nil)
				return updateMarker, mockRollbackSource
			},
			postNormalizeAssertions: nil,
		},
		{
			name: "Entries not having a matching install directory will be removed from the list",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, rollbacksSource) {
				_ = createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				mockRollbackSource := newMockRollbacksSource(t)
				nonExistingVersionedHome := filepath.Join("data", "thisdirectorydoesnotexist")
				mockRollbackSource.EXPECT().Get().Return(map[string]ttl.TTLMarker{
					oldAgentInstallPath: {
						Version:    "1.2.3",
						Hash:       "oldversionhash",
						ValidUntil: tomorrow,
					},
					nonExistingVersionedHome: {
						Version:    "0.0.0",
						Hash:       "nonExistingHash",
						ValidUntil: tomorrow,
					},
				}, nil)

				return nil, mockRollbackSource
			},
			postNormalizeAssertions: nil,
		},
		{
			name: "Expired installs still existing on disk will be removed from the install list and removed from disk",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, rollbacksSource) {
				_ = createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				// assert that the versionedHome of the old install is the same we check in postNormalizeAssertions
				assert.Equal(t, oldAgentInstallPath, filepath.Join("data", "elastic-agent-1.2.3-oldver"),
					"Unexpected old install versioned home. Post normalize assertions may not be working")

				mockRollbackSource := newMockRollbacksSource(t)
				mockRollbackSource.EXPECT().Get().Return(
					map[string]ttl.TTLMarker{
						oldAgentInstallPath: {
							Version:    "1.2.3",
							Hash:       "oldver",
							ValidUntil: yesterday,
						},
					},
					nil,
				)

				mockRollbackSource.EXPECT().Remove(filepath.Join("data", "elastic-agent-1.2.3-oldver")).Return(nil)
				return nil, mockRollbackSource
			},
			postNormalizeAssertions: func(t *testing.T, topDir string, _ *upgrade.UpdateMarker) {
				assert.NoDirExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-oldver"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := loggertest.New(t.Name())
			tmpDir := t.TempDir()
			updateMarker, installSource := tt.setup(t, tmpDir)
			normalizeAgentInstalls(logger, tmpDir, now, updateMarker, installSource)
			if tt.postNormalizeAssertions != nil {
				tt.postNormalizeAssertions(t, tmpDir, updateMarker)
			}
		})
	}
}

// createFakeAgentInstall (copied from the upgrade package tests) will create a mock agent install within topDir, possibly
// using the version in the directory name, depending on useVersionInPath it MUST return the path to the created versionedHome
// relative to topDir, to mirror what step_unpack returns
func createFakeAgentInstall(t *testing.T, topDir, version, hash string, useVersionInPath bool) string {

	// create versioned home
	versionedHome := fmt.Sprintf("elastic-agent-%s", hash[:upgrade.HashLen])
	if useVersionInPath {
		// use the version passed as parameter
		versionedHome = fmt.Sprintf("elastic-agent-%s-%s", version, hash[:upgrade.HashLen])
	}
	relVersionedHomePath := filepath.Join("data", versionedHome)
	absVersionedHomePath := filepath.Join(topDir, relVersionedHomePath)

	// recalculate the binary path and launch a mkDirAll to account for MacOS weirdness
	// (the extra nesting of elastic agent binary within versionedHome)
	absVersioneHomeBinaryPath := paths.BinaryPath(absVersionedHomePath, "")
	err := os.MkdirAll(absVersioneHomeBinaryPath, 0o750)
	require.NoError(t, err, "error creating fake install versioned home directory (including binary path) %q", absVersioneHomeBinaryPath)

	// place a few directories in the fake install
	absComponentsDirPath := filepath.Join(absVersionedHomePath, "components")
	err = os.MkdirAll(absComponentsDirPath, 0o750)
	require.NoError(t, err, "error creating fake install components directory %q", absVersionedHomePath)

	absLogsDirPath := filepath.Join(absVersionedHomePath, "logs")
	err = os.MkdirAll(absLogsDirPath, 0o750)
	require.NoError(t, err, "error creating fake install logs directory %q", absLogsDirPath)

	absRunDirPath := filepath.Join(absVersionedHomePath, "run")
	err = os.MkdirAll(absRunDirPath, 0o750)
	require.NoError(t, err, "error creating fake install run directory %q", absRunDirPath)

	// put some placeholder for files
	agentExecutableName := upgrade.AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}
	err = os.WriteFile(paths.BinaryPath(absVersionedHomePath, agentExecutableName), fmt.Appendf(nil, "Placeholder for agent %s", version), 0o750)
	require.NoErrorf(t, err, "error writing elastic agent binary placeholder %q", agentExecutableName)
	fakeLogPath := filepath.Join(absLogsDirPath, "fakelog.ndjson")
	err = os.WriteFile(fakeLogPath, fmt.Appendf(nil, "Sample logs for agent %s", version), 0o750)
	require.NoErrorf(t, err, "error writing fake log placeholder %q", fakeLogPath)

	// return the path relative to top exactly like the step_unpack does
	return relVersionedHomePath
}

func TestApplicationStandaloneEncrypted(t *testing.T) {
	log, _ := loggertest.New("TestApplicationStandaloneEncrypted")

	cfgPath := paths.Config()
	t.Cleanup(func() { paths.SetConfig(cfgPath) })

	paths.SetConfig(t.TempDir())
	err := os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: true
  logging:
    level: debug`), 0640)
	require.NoError(t, err)

	t.Log("Ensure New encrypts config")
	startupCfg, cfg := loadTestConfig(t)
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		startupCfg,
		cfg,
		nil,
		nil,
	)
	require.NoError(t, err)

	encBytes, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Ensure New does not alter contents when no changes are made")
	startupCfg, cfg = loadTestConfig(t)
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		startupCfg,
		cfg,
		nil,
		nil,
	)
	require.NoError(t, err)
	encBytes2, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, encBytes, encBytes2, "fleet.enc contents have chagned")

	ymlBytes, err = os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Change elastic-agent.yml to have same contents with different structure, should not re-encrypt")
	err = os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: true`), 0640)
	require.NoError(t, err)

	startupCfg, cfg = loadTestConfig(t)
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		startupCfg,
		cfg,
		nil,
		nil,
	)
	require.NoError(t, err)
	encBytes3, err := os.ReadFile(paths.AgentConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, encBytes, encBytes3, "fleet.enc contents have chagned")

	ymlBytes, err = os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.NotEqualValues(t, storage.DefaultAgentEncryptedStandaloneConfig, ymlBytes, "unexpected contents in elastic-agent.yml")

	t.Log("Ensure that setting encrypted_config to false works")
	err = os.WriteFile(paths.ConfigFile(), []byte(`agent:
  features:
    encrypted_config:
      enabled: false
  logging:
    level: debug`), 0640)
	require.NoError(t, err)

	startupCfg, cfg = loadTestConfig(t)
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		startupCfg,
		cfg,
		nil,
		nil,
	)
	require.NoError(t, err)
}

func TestHasEncryptedStandaloneConfigChanged(t *testing.T) {
	log, _ := loggertest.New("TestHasEncryptedStandaloneConfigChanged")
	tests := []struct {
		name     string
		contents []byte
		expect   bool
	}{{
		name:     "no change",
		contents: storage.DefaultAgentEncryptedStandaloneConfig,
		expect:   false,
	}, {
		name: "contents change",
		contents: []byte(`agent:
  features:
    encrypted_config:
      enabled: true
    fqdn:
      enabled: true
`),
		expect: true,
	}, {
		name:     "no file contents",
		contents: []byte{},
		expect:   true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "a.yml")
			err := os.WriteFile(path, tt.contents, 0640)
			require.NoError(t, err)
			changed := hasEncryptedStandaloneConfigChanged(log, path)
			require.Equal(t, tt.expect, changed)
		})
	}
}

func TestApplicationStandaloneEncryptedWithFleetEnabled(t *testing.T) {
	log, _ := loggertest.New("TestApplicationStandaloneEncryptedWithFleetEnabled")

	cfgPath := paths.Config()
	t.Cleanup(func() { paths.SetConfig(cfgPath) })
	paths.SetConfig(t.TempDir())

	err := os.WriteFile(paths.ConfigFile(), DefaultAgentFleetConfig, 0640)
	require.NoError(t, err)

	isRoot, err := utils.HasRoot()
	require.NoError(t, err)
	err = secret.CreateAgentSecret(t.Context(), vault.WithUnprivileged(!isRoot), vault.WithVaultPath(filepath.Join(paths.Config(), paths.DefaultAgentVaultPath)))
	require.NoError(t, err)
	encStore, err := storage.NewEncryptedDiskStore(t.Context(), filepath.Join(paths.Config(), paths.DefaultAgentFleetFile), storage.WithVaultPath(filepath.Join(paths.Config(), paths.DefaultAgentVaultPath)))
	require.NoError(t, err)
	err = encStore.Save(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "exampleKey"
  host: https://localhost:8220`))
	require.NoError(t, err)

	startupCfg, cfg := loadTestConfig(t)
	_, _, _, err = New(
		t.Context(),
		log,
		log,
		logp.DebugLevel,
		&info.AgentInfo{},
		nil,
		nil,
		false, // not in testing mode - we are testing fs interactions
		time.Second,
		true,
		startupCfg,
		cfg,
		nil,
		nil,
	)
	require.NoError(t, err)

	ymlBytes, err := os.ReadFile(paths.ConfigFile())
	require.NoError(t, err)
	require.EqualValues(t, DefaultAgentFleetConfig, ymlBytes, "unexpected contents in elastic-agent.yml")
}

func loadTestConfig(t *testing.T) (startupCfg, cfg *configuration.Configuration) {
	t.Helper()

	reloader, err := configuration.NewConfigReloader(t.Context(), nil, nil)
	require.NoError(t, err)
	return reloader.StartupConfiguration(), reloader.Configuration()
}

// seedBuildLogs creates the log directory of a build under topDir whose only file was last written age ago.
func seedBuildLogs(t *testing.T, topDir, name string, age time.Duration) {
	t.Helper()
	dir := filepath.Join(paths.BuildLogsRoot(topDir), name)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	f := filepath.Join(dir, "elastic-agent-1.ndjson")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	ts := time.Now().Add(-age)
	require.NoError(t, os.Chtimes(f, ts, ts))
}

func TestCleanupOldBuildLogs(t *testing.T) {
	t.Run("keeps the running build and the latest inactive one", func(t *testing.T) {
		topDir := t.TempDir()
		// the running build is kept even though it was written the longest ago
		seedBuildLogs(t, topDir, "9.0.2-cccccc", 3*time.Hour)
		seedBuildLogs(t, topDir, "9.0.0-aaaaaa", 2*time.Hour)
		seedBuildLogs(t, topDir, "9.0.1-bbbbbb", time.Hour)

		log, _ := loggertest.New(t.Name())
		CleanupOldBuildLogs(t.Context(), log, topDir, "9.0.2-cccccc")

		root := paths.BuildLogsRoot(topDir)
		assert.DirExists(t, filepath.Join(root, "9.0.2-cccccc"))
		assert.DirExists(t, filepath.Join(root, "9.0.1-bbbbbb"))
		assert.NoDirExists(t, filepath.Join(root, "9.0.0-aaaaaa"))
	})

	t.Run("unversioned home keeps all logs", func(t *testing.T) {
		paths.SetVersionHome(false)
		t.Cleanup(func() { paths.SetVersionHome(true) })
		topDir := t.TempDir()
		seedBuildLogs(t, topDir, "9.0.0-aaaaaa", 2*time.Hour)
		seedBuildLogs(t, topDir, "9.0.1-bbbbbb", time.Hour)

		log, _ := loggertest.New(t.Name())
		CleanupOldBuildLogs(t.Context(), log, topDir, "9.0.2-cccccc")

		assert.DirExists(t, filepath.Join(paths.BuildLogsRoot(topDir), "9.0.0-aaaaaa"))
		assert.DirExists(t, filepath.Join(paths.BuildLogsRoot(topDir), "9.0.1-bbbbbb"))
	})

	t.Run("stops when the context is done without reporting a failure", func(t *testing.T) {
		topDir := t.TempDir()
		seedBuildLogs(t, topDir, "9.0.2-cccccc", 3*time.Hour)
		seedBuildLogs(t, topDir, "9.0.0-aaaaaa", 2*time.Hour)
		seedBuildLogs(t, topDir, "9.0.1-bbbbbb", time.Hour)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		log, obs := loggertest.New(t.Name())
		CleanupOldBuildLogs(ctx, log, topDir, "9.0.2-cccccc")

		assert.DirExists(t, filepath.Join(paths.BuildLogsRoot(topDir), "9.0.0-aaaaaa"), "nothing is removed once the Agent stops")
		assert.Zero(t, obs.FilterLevelExact(zapcore.WarnLevel).Len(), "stopping is not a failure: %v", obs.All())
	})

	t.Run("reports a failure as a warning", func(t *testing.T) {
		topDir := t.TempDir()
		outside := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(paths.BuildLogsRoot(topDir), ".."), 0o755))
		if err := os.Symlink(outside, paths.BuildLogsRoot(topDir)); err != nil {
			t.Skipf("cannot create symbolic links: %s", err)
		}

		log, obs := loggertest.New(t.Name())
		CleanupOldBuildLogs(t.Context(), log, topDir, "9.0.2-cccccc")

		warnings := obs.FilterLevelExact(zapcore.WarnLevel).All()
		require.Len(t, warnings, 1, "logs: %v", obs.All())
		assert.Contains(t, warnings[0].Message, "Error cleaning build logs")
	})
}
