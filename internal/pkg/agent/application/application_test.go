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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/limits"
)

func TestMergeFleetConfig(t *testing.T) {
	testutils.InitStorage(t)

	cfg := map[string]interface{}{
		"fleet": map[string]interface{}{
			"enabled":        true,
			"kibana":         map[string]interface{}{"host": "demo"},
			"access_api_key": "123",
		},
		"agent": map[string]interface{}{
			"grpc": map[string]interface{}{
				"port": uint16(6790),
			},
		},
	}

	rawConfig := config.MustNewConfigFrom(cfg)
	storage, conf, err := mergeFleetConfig(context.Background(), rawConfig)
	require.NoError(t, err)
	assert.NotNil(t, storage)
	assert.NotNil(t, conf)
	assert.Equal(t, conf.Fleet.Enabled, cfg["fleet"].(map[string]interface{})["enabled"])
	assert.Equal(t, conf.Fleet.AccessAPIKey, cfg["fleet"].(map[string]interface{})["access_api_key"])
	assert.Equal(t, conf.Settings.GRPC.Port, cfg["agent"].(map[string]interface{})["grpc"].(map[string]interface{})["port"].(uint16))
}

func TestLimitsLog(t *testing.T) {
	log, obs := loggertest.New("TestLimitsLog")
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

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
		nil,               // no configuration overrides
		nil,
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
		setup                   func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource)
		postNormalizeAssertions func(t *testing.T, topDir string, initialUpdateMarker *upgrade.UpdateMarker)
	}{
		{
			name: "happy path: single install, no modifications needed",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource) {
				mockInstallSource := newMockInstallDescriptorSource(t)
				mockInstallSource.EXPECT().GetInstallDesc().Return(
					&v1.InstallDescriptor{
						AgentInstalls: []v1.AgentInstallDesc{
							{
								Version:       "1.2.3-current",
								Hash:          "current",
								VersionedHome: filepath.Join("data", "elastic-agent-1.2.3-curren"),
								Flavor:        "basic",
								Active:        true,
							},
						},
					},
					nil,
				)
				return nil, mockInstallSource
			},

			postNormalizeAssertions: nil,
		},
		{
			name: "Agent was manually rolled back: rolled back install is removed from the list",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource) {
				newAgentInstallPath := createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				mockInstallSource := newMockInstallDescriptorSource(t)
				fakeInstallDescriptor := v1.InstallDescriptor{
					AgentInstalls: []v1.AgentInstallDesc{
						{
							Version:       "4.5.6",
							Hash:          "newversionhash",
							VersionedHome: newAgentInstallPath,
							Flavor:        "basic",
							Active:        true,
						},
						{
							Version:         "1.2.3",
							Hash:            "oldversionhash",
							VersionedHome:   oldAgentInstallPath,
							Flavor:          "basic",
							OptionalTTLItem: v1.OptionalTTLItem{TTL: &tomorrow},
						},
					},
				}
				mockInstallSource.EXPECT().GetInstallDesc().Return(
					&fakeInstallDescriptor,
					nil,
				)
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

				mockInstallSource.EXPECT().ModifyInstallDesc(mock.Anything).RunAndReturn(func(f func(*v1.AgentInstallDesc) error) (*v1.InstallDescriptor, error) {

					for i := range fakeInstallDescriptor.AgentInstalls {
						err := f(&fakeInstallDescriptor.AgentInstalls[i])
						assert.NoErrorf(t, err, "unexpected error while modifying install descriptor %+v", i)
					}

					assert.False(t, fakeInstallDescriptor.AgentInstalls[0].Active, "install we rolled back from should be set to not active")
					assert.False(t, fakeInstallDescriptor.AgentInstalls[0].Active, "install we rolled back to should be set to active")
					return &fakeInstallDescriptor, nil
				})

				// returned modified install descriptor content is not important
				mockInstallSource.EXPECT().RemoveAgentInstallDesc(newAgentInstallPath).Return(&fakeInstallDescriptor, nil)

				return updateMarker, mockInstallSource
			},
			postNormalizeAssertions: nil,
		},
		{
			name: "Entries not having a matching install directory will be removed from the list",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource) {
				newAgentInstallPath := createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				mockInstallSource := newMockInstallDescriptorSource(t)
				nonExistingVersionedHome := filepath.Join("data", "thisdirectorydoesnotexist")
				fakeInstallDescriptor := v1.InstallDescriptor{
					AgentInstalls: []v1.AgentInstallDesc{
						{
							Version:       "4.5.6",
							Hash:          "currentVersionHash",
							VersionedHome: newAgentInstallPath,
							Flavor:        "basic",
							Active:        true,
						},
						{
							Version:         "1.2.3",
							Hash:            "oldversionhash",
							VersionedHome:   oldAgentInstallPath,
							Flavor:          "basic",
							OptionalTTLItem: v1.OptionalTTLItem{TTL: &tomorrow},
						},
						{
							Version:       "0.0.0",
							Hash:          "nonExistingHash",
							VersionedHome: nonExistingVersionedHome,
							Flavor:        "basic",
						},
					},
				}
				mockInstallSource.EXPECT().GetInstallDesc().Return(
					&fakeInstallDescriptor,
					nil,
				)

				// returned modified install descriptor content is not important
				mockInstallSource.EXPECT().RemoveAgentInstallDesc(nonExistingVersionedHome).Return(&fakeInstallDescriptor, nil)

				return nil, mockInstallSource
			},
			postNormalizeAssertions: nil,
		},
		{
			name: "Expired installs still existing on disk will be removed from the install list and removed from disk",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource) {
				newAgentInstallPath := createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				// assert that the versionedHome of the old install is the same we check in postNormalizeAssertions
				assert.Equal(t, oldAgentInstallPath, filepath.Join("data", "elastic-agent-1.2.3-oldver"),
					"Unexpected old install versioned home. Post normalize assertions may not be working")

				mockInstallSource := newMockInstallDescriptorSource(t)
				fakeInstallDescriptor := v1.InstallDescriptor{
					AgentInstalls: []v1.AgentInstallDesc{
						{
							Version:       "4.5.6",
							Hash:          "newversionhash",
							VersionedHome: newAgentInstallPath,
							Flavor:        "basic",
							Active:        true,
						},
						{
							Version:         "1.2.3",
							Hash:            "oldversionhash",
							VersionedHome:   oldAgentInstallPath,
							Flavor:          "basic",
							OptionalTTLItem: v1.OptionalTTLItem{TTL: &yesterday},
						},
					},
				}
				mockInstallSource.EXPECT().GetInstallDesc().Return(
					&fakeInstallDescriptor,
					nil,
				)

				mockInstallSource.EXPECT().RemoveAgentInstallDesc(oldAgentInstallPath).Return(&fakeInstallDescriptor, nil)

				return nil, mockInstallSource
			},
			postNormalizeAssertions: func(t *testing.T, topDir string, _ *upgrade.UpdateMarker) {
				assert.NoDirExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-oldver"))
			},
		},
		{
			name: "If a directory cannot be checked, the entry is left alone in the installDescriptor (with a warning in the logs)",
			setup: func(t *testing.T, topDir string) (*upgrade.UpdateMarker, installDescriptorSource) {

				if runtime.GOOS == "windows" {
					t.Skipf("This test rely on permission settings not available on Windows")
				}

				newAgentInstallPath := createFakeAgentInstall(t, topDir, "4.5.6", "newversionhash", true)
				oldAgentInstallPath := createFakeAgentInstall(t, topDir, "1.2.3", "oldversionhash", true)

				// assert that the versionedHome of the old install is the same we check in postNormalizeAssertions
				assert.Equal(t, oldAgentInstallPath, filepath.Join("data", "elastic-agent-1.2.3-oldver"),
					"Unexpected old install versioned home. Post normalize assertions may not be working")

				// make `data` unreadable
				dataDir := paths.DataFrom(topDir)
				dataStat, err := os.Stat(dataDir)
				require.NoError(t, err, "data should be accessible")
				err = os.Chmod(dataDir, 0o222)
				require.NoError(t, err, "Error making data unreadable")

				//restore data permissions on test exit
				t.Cleanup(func() {
					cleanupErr := os.Chmod(dataDir, dataStat.Mode())
					assert.NoError(t, cleanupErr, "error restoring data permissions")
				})

				_, err = os.Stat(filepath.Join(topDir, newAgentInstallPath))
				require.Errorf(t, err, "os.Stat on %s shoud not be successful", newAgentInstallPath)

				_, err = os.Stat(filepath.Join(topDir, oldAgentInstallPath))
				require.Errorf(t, err, "os.Stat on %s shoud not be successful", oldAgentInstallPath)

				mockInstallSource := newMockInstallDescriptorSource(t)
				fakeInstallDescriptor := v1.InstallDescriptor{
					AgentInstalls: []v1.AgentInstallDesc{
						{
							Version:       "4.5.6",
							Hash:          "newversionhash",
							VersionedHome: newAgentInstallPath,
							Flavor:        "basic",
							Active:        true,
						},
						{
							Version:         "1.2.3",
							Hash:            "oldversionhash",
							VersionedHome:   oldAgentInstallPath,
							Flavor:          "basic",
							OptionalTTLItem: v1.OptionalTTLItem{TTL: &yesterday},
						},
					},
				}
				mockInstallSource.EXPECT().GetInstallDesc().Return(
					&fakeInstallDescriptor,
					nil,
				)

				return nil, mockInstallSource
			},
			postNormalizeAssertions: func(t *testing.T, topDir string, _ *upgrade.UpdateMarker) {
				// make data readable again
				dataDir := paths.DataFrom(topDir)
				err := os.Chmod(dataDir, 0o755)
				require.NoError(t, err, "error reopening data permissions")
				assert.DirExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-oldver"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := loggertest.New(t.Name())
			tmpDir := t.TempDir()
			updateMarker, installSource := tt.setup(t, tmpDir)
			normalizeInstallDescriptorAtStartup(logger, tmpDir, now, updateMarker, installSource)
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
	err = os.WriteFile(paths.BinaryPath(absVersionedHomePath, agentExecutableName), []byte(fmt.Sprintf("Placeholder for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing elastic agent binary placeholder %q", agentExecutableName)
	fakeLogPath := filepath.Join(absLogsDirPath, "fakelog.ndjson")
	err = os.WriteFile(fakeLogPath, []byte(fmt.Sprintf("Sample logs for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing fake log placeholder %q", fakeLogPath)

	// return the path relative to top exactly like the step_unpack does
	return relVersionedHomePath
}
