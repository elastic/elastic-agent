// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type hookFunc func(t *testing.T, topDir string)

type testAgentVersion struct {
	version string
	hash    string
}

type testAgentInstall struct {
	version          testAgentVersion
	useVersionInPath bool
}

type setupAgentInstallations struct {
	installedAgents []testAgentInstall
	upgradeFrom     testAgentVersion
	upgradeTo       testAgentVersion
	currentAgent    testAgentVersion
}

var (
	version123Snapshot = testAgentVersion{
		version: "1.2.3-SNAPSHOT",
		hash:    "abcdef",
	}
	version456Snapshot = testAgentVersion{
		version: "4.5.6-SNAPSHOT",
		hash:    "ghijkl",
	}
)

func TestCleanup(t *testing.T) {
	type args struct {
		currentVersionedHome string
		currentHash          string
		removeMarker         bool
		keepLogs             bool
	}

	tests := map[string]struct {
		args               args
		agentInstallsSetup setupAgentInstallations
		additionalSetup    hookFunc
		wantErr            assert.ErrorAssertionFunc
		checkAfterCleanup  hookFunc
	}{
		"cleanup without versionedHome (legacy upgrade process)": {
			args: args{
				currentVersionedHome: "data/elastic-agent-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: false,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: false,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterCleanup: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-ghijkl")
				checkFilesAfterCleanup(t, topDir, newAgentHome, oldAgentHome)
			},
		},
		"cleanup with versionedHome (new upgrade process)": {
			args: args{
				currentVersionedHome: "data/elastic-agent-4.5.6-SNAPSHOT-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterCleanup: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
				checkFilesAfterCleanup(t, topDir, newAgentHome, oldAgentHome)
			},
		},
		"cleanup with versionedHome only on the new agent (new upgrade process from an old agent upgraded with legacy process)": {
			args: args{
				currentVersionedHome: "data/elastic-agent-4.5.6-SNAPSHOT-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: false,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterCleanup: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
				checkFilesAfterCleanup(t, topDir, newAgentHome, oldAgentHome)
			},
		},
		"cleanup with versionedHome only on the new agent + extra old agent installs": {
			args: args{
				currentVersionedHome: "data/elastic-agent-4.5.6-SNAPSHOT-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version: testAgentVersion{
							version: "0.9.9",
							hash:    "aaaaaa",
						},
						useVersionInPath: false,
					},
					{
						version: testAgentVersion{
							version: "1.1.1",
							hash:    "aaabbb",
						},
						useVersionInPath: false,
					},
					{
						version:          version123Snapshot,
						useVersionInPath: false,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterCleanup: func(t *testing.T, topDir string) {
				newAgentHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
				oldAgentHomes := []string{
					filepath.Join("data", "elastic-agent-abcdef"),
					filepath.Join("data", "elastic-agent-aaabbb"),
					filepath.Join("data", "elastic-agent-aaaaaa"),
				}

				checkFilesAfterCleanup(t, topDir, newAgentHome, oldAgentHomes...)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testLogger, _ := loggertest.New(t.Name())
			testTop := t.TempDir()
			setupAgents(t, testLogger, testTop, tt.agentInstallsSetup, true)
			if tt.additionalSetup != nil {
				tt.additionalSetup(t, testTop)
			}
			marker, err := LoadMarker(paths.DataFrom(testTop))
			require.NoError(t, err, "error loading update marker")
			require.NotNil(t, marker, "loaded marker must not be nil")
			t.Logf("Loaded update marker %+v", marker)
			versionedHome := marker.VersionedHome
			if versionedHome == "" {
				versionedHome = filepath.Join("data", fmt.Sprintf("elastic-agent-%s", marker.Hash[:6]))
			}
			tt.wantErr(t, cleanup(testLogger, testTop, tt.args.removeMarker, tt.args.keepLogs, 0, versionedHome), fmt.Sprintf("Cleanup(%v, %v, %v, %v)", marker.Hash, tt.args.removeMarker, tt.args.keepLogs, versionedHome))
			tt.checkAfterCleanup(t, testTop)
		})
	}
}

// TestCleanup_PreservesLiveVersionedHome ensures cleanup() always keeps the
// directory backing the live agent symlink, even when the caller's keep list
// does not reference it. Closes the data-loss path described in
// https://github.com/elastic/elastic-agent/issues/13505.
func TestCleanup_PreservesLiveVersionedHome(t *testing.T) {
	testLogger, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	// Two installs; the symlink points at the older one (the live install).
	liveHome := createFakeAgentInstall(t, topDir, version123Snapshot.version, version123Snapshot.hash, true)
	otherHome := createFakeAgentInstall(t, topDir, version456Snapshot.version, version456Snapshot.hash, true)
	createLink(t, topDir, liveHome)

	// Caller passes a keep list that omits the live install.
	err := cleanup(testLogger, topDir, false, false, 0, otherHome)
	require.NoError(t, err)

	// Both installs must remain: otherHome because it's in the keep list, liveHome because it's the symlink target.
	assert.DirExists(t, filepath.Join(topDir, liveHome),
		"live versioned home must be preserved by the cleanup guard")
	assert.DirExists(t, filepath.Join(topDir, otherHome))
}

// TestCleanup_IgnoresNonExistentKeepListEntry ensures cleanup() treats a
// non-existent keep-list entry as a no-op: the live install survives, and the
// "Keeping" log line only mentions directories that actually exist on disk.
func TestCleanup_IgnoresNonExistentKeepListEntry(t *testing.T) {
	testLogger, obs := loggertest.New(t.Name())
	topDir := t.TempDir()

	// One real install + symlink, plus a phantom path the caller insists on.
	liveHome := createFakeAgentInstall(t, topDir, version123Snapshot.version, version123Snapshot.hash, true)
	createLink(t, topDir, liveHome)
	phantomHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-deadbeef")

	err := cleanup(testLogger, topDir, false, false, 0, phantomHome)
	require.NoError(t, err)

	// Live install must survive even when the keep-list entry does not exist on disk.
	assert.DirExists(t, filepath.Join(topDir, liveHome))

	// "Starting cleanup" log line must NOT mention the phantom entry; only the real
	// live install should be listed in the "keep" field.
	keepLogs := obs.FilterMessageSnippet("Starting cleanup of versioned homes").All()
	if assert.Len(t, keepLogs, 1) {
		keepField, _ := keepLogs[0].ContextMap()["to_keep"].([]interface{})
		for _, entry := range keepField {
			assert.NotContains(t, fmt.Sprintf("%v", entry), "deadbeef",
				"keep-list log must not contain phantom entry")
		}
	}
}

func TestRollback(t *testing.T) {
	tests := map[string]struct {
		agentInstallsSetup setupAgentInstallations
		additionalSetup    hookFunc
		wantErr            assert.ErrorAssertionFunc
		checkAfterRollback hookFunc
	}{
		"rollback without versionedHome (legacy upgrade process)": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: false,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: false,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-ghijkl")
				checkFilesAfterRollback(t, topDir, oldAgentHome, newAgentHome)
			},
		},
		"rollback with versionedHome (new upgrade process)": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
				checkFilesAfterRollback(t, topDir, oldAgentHome, newAgentHome)
			},
		},
		"rollback with versionedHome only on the new agent (new upgrade process from an old agent upgraded with legacy process)": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: false,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, topDir string) {
				oldAgentHome := filepath.Join("data", "elastic-agent-abcdef")
				newAgentHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
				checkFilesAfterRollback(t, topDir, oldAgentHome, newAgentHome)
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testLogger, _ := loggertest.New(t.Name())
			testTop := t.TempDir()
			setupAgents(t, testLogger, testTop, tt.agentInstallsSetup, true)
			if tt.additionalSetup != nil {
				tt.additionalSetup(t, testTop)
			}
			marker, err := LoadMarker(paths.DataFrom(testTop))
			require.NoError(t, err, "error loading update marker")
			require.NotNil(t, marker, "loaded marker must not be nil")
			t.Logf("Loaded update marker %+v", marker)

			// mock client
			mockClient := client.NewMockClient(t)
			mockClient.EXPECT().Connect(
				mock.AnythingOfType("*context.timerCtx"),
				mock.AnythingOfType("*grpc.funcDialOption"),
				mock.AnythingOfType("*grpc.funcDialOption"),
			).Return(nil)
			mockClient.EXPECT().Disconnect().Return()
			mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

			ctx := context.TODO()
			tt.wantErr(t, Rollback(ctx, testLogger, mockClient, testTop, marker.PrevVersionedHome, marker.PrevHash), fmt.Sprintf("Rollback(%v, %v, %v, %v, %v, %v)", ctx, testLogger, mockClient, testTop, marker.PrevVersionedHome, marker.PrevHash))
			tt.checkAfterRollback(t, testTop)
		})
	}
}

func TestRollbackWithOpts(t *testing.T) {
	type hookFuncWithLogs func(t *testing.T, logs *observer.ObservedLogs, topDir string)

	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	type args struct {
		prevVersionedHome string
		prevHash          string
		rollbackOptions   []RollbackOpt
	}

	tests := map[string]struct {
		agentInstallsSetup setupAgentInstallations
		setupMocks         func(*client.MockClient)
		args               args
		wantErr            assert.ErrorAssertionFunc
		checkAfterRollback hookFuncWithLogs
	}{
		"SkipCleanup: leave the current installation intact": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			setupMocks: func(mockClient *client.MockClient) {
				mockClient.EXPECT().Connect(
					mock.AnythingOfType("*context.timerCtx"),
					mock.AnythingOfType("*grpc.funcDialOption"),
					mock.AnythingOfType("*grpc.funcDialOption"),
				).Return(nil)
				mockClient.EXPECT().Disconnect().Return()
				mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()
			},
			args: args{
				prevVersionedHome: "data/elastic-agent-1.2.3-SNAPSHOT-abcdef",
				prevHash:          "abcdef",
				rollbackOptions: []RollbackOpt{
					func(rs *RollbackSettings) { rs.SetSkipCleanup(true) },
				},
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, _ *observer.ObservedLogs, topDir string) {
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName)
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl"), agentExecutableName)
				linkTarget, err := os.Readlink(filepath.Join(topDir, agentExecutableName))
				assert.NoError(t, err, "reading topPath elastic-agent link")
				assert.Equal(t, paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName), linkTarget)
				assert.FileExists(t, filepath.Join(topDir, "data", markerFilename))
			},
		},
		"SkipRestart: no cleanup, no restart": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			setupMocks: func(mockClient *client.MockClient) {
				// nothing to do here, no restart will be issued
			},
			args: args{
				prevVersionedHome: "data/elastic-agent-1.2.3-SNAPSHOT-abcdef",
				prevHash:          "abcdef",
				rollbackOptions: []RollbackOpt{
					func(rs *RollbackSettings) { rs.SetSkipRestart(true) },
				},
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, _ *observer.ObservedLogs, topDir string) {
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName)
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl"), agentExecutableName)
				linkTarget, err := os.Readlink(filepath.Join(topDir, agentExecutableName))
				assert.NoError(t, err, "reading topPath elastic-agent link")
				assert.Equal(t, paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName), linkTarget)
				assert.FileExists(t, filepath.Join(topDir, "data", markerFilename))
			},
		},
		"Prerestart hook not fatal error: rollback, cleanup and restart as normal": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			setupMocks: func(mockClient *client.MockClient) {
				mockClient.EXPECT().Connect(
					mock.AnythingOfType("*context.timerCtx"),
					mock.AnythingOfType("*grpc.funcDialOption"),
					mock.AnythingOfType("*grpc.funcDialOption"),
				).Return(nil)
				mockClient.EXPECT().Disconnect().Return()
				mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()
			},
			args: args{
				prevVersionedHome: "data/elastic-agent-1.2.3-SNAPSHOT-abcdef",
				prevHash:          "abcdef",
				rollbackOptions: []RollbackOpt{
					func(rs *RollbackSettings) {
						rs.SetPreRestartHook(func(ctx context.Context, log *logger.Logger, topDirPath string) error {
							return errors.New("pre-restart hook error, not fatal")
						})
					},
				},
			},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, logs *observer.ObservedLogs, topDir string) {
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName)
				assertAgentInstallCleaned(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl"), agentExecutableName)
				linkTarget, err := os.Readlink(filepath.Join(topDir, agentExecutableName))
				assert.NoError(t, err, "reading topPath elastic-agent link")
				assert.Equal(t, paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName), linkTarget)
				snippetLogs := logs.FilterMessageSnippet("pre-restart hook error, not fatal").All()
				assert.Len(t, snippetLogs, 1)
				assert.FileExists(t, filepath.Join(topDir, "data", markerFilename))
			},
		},
		"Prerestart hook fatal error: rollback then return the error (no restart, no cleanup)": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			setupMocks: func(mockClient *client.MockClient) {
				// no restart request should be made
			},
			args: args{
				prevVersionedHome: "data/elastic-agent-1.2.3-SNAPSHOT-abcdef",
				prevHash:          "abcdef",
				rollbackOptions: []RollbackOpt{
					func(rs *RollbackSettings) {
						rs.SetPreRestartHook(func(ctx context.Context, log *logger.Logger, topDirPath string) error {
							return fmt.Errorf("fatal pre-restart hook error: %w", FatalRollbackError)
						})
					},
				},
			},
			wantErr: assert.Error,
			checkAfterRollback: func(t *testing.T, logs *observer.ObservedLogs, topDir string) {
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName)
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl"), agentExecutableName)
				linkTarget, err := os.Readlink(filepath.Join(topDir, agentExecutableName))
				assert.NoError(t, err, "reading topPath elastic-agent link")
				assert.Equal(t, paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName), linkTarget)
				assert.FileExists(t, filepath.Join(topDir, "data", markerFilename))
			},
		},
		"RemoveMarker true: delete the upgrade marker": {
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []testAgentInstall{
					{
						version:          version123Snapshot,
						useVersionInPath: true,
					},
					{
						version:          version456Snapshot,
						useVersionInPath: true,
					},
				},
				upgradeFrom:  version123Snapshot,
				upgradeTo:    version456Snapshot,
				currentAgent: version456Snapshot,
			},
			setupMocks: func(mockClient *client.MockClient) {
				mockClient.EXPECT().Connect(
					mock.AnythingOfType("*context.timerCtx"),
					mock.AnythingOfType("*grpc.funcDialOption"),
					mock.AnythingOfType("*grpc.funcDialOption"),
				).Return(nil)
				mockClient.EXPECT().Disconnect().Return()
				mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()
			},
			args: args{
				prevVersionedHome: "data/elastic-agent-1.2.3-SNAPSHOT-abcdef",
				prevHash:          "abcdef",
				rollbackOptions: []RollbackOpt{
					func(rs *RollbackSettings) {
						rs.SetRemoveMarker(true)
					},
				}},
			wantErr: assert.NoError,
			checkAfterRollback: func(t *testing.T, logs *observer.ObservedLogs, topDir string) {
				assertAgentInstallExists(t, filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName)
				assertAgentInstallCleaned(t, filepath.Join(topDir, "data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl"), agentExecutableName)
				linkTarget, err := os.Readlink(filepath.Join(topDir, agentExecutableName))
				assert.NoError(t, err, "reading topPath elastic-agent link")
				assert.Equal(t, paths.BinaryPath(filepath.Join(topDir, "data", "elastic-agent-1.2.3-SNAPSHOT-abcdef"), agentExecutableName), linkTarget)
				assert.NoFileExists(t, filepath.Join(topDir, "data", markerFilename))
			},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testLogger, obsLogs := loggertest.New(t.Name())
			testTop := t.TempDir()
			setupAgents(t, testLogger, testTop, tt.agentInstallsSetup, true)

			// mock client
			mockClient := client.NewMockClient(t)
			tt.setupMocks(mockClient)

			tt.wantErr(t, RollbackWithOpts(t.Context(), testLogger, mockClient, testTop, tt.args.prevVersionedHome, tt.args.prevHash, tt.args.rollbackOptions...))
			tt.checkAfterRollback(t, obsLogs, testTop)
		})
	}
}

func assertAgentInstallExists(t *testing.T, versionedHome string, agentExecutableName string) {
	assert.DirExists(t, versionedHome)
	assert.FileExists(t, paths.BinaryPath(versionedHome, agentExecutableName))
	assert.DirExists(t, filepath.Join(versionedHome, "logs"))
	assert.DirExists(t, filepath.Join(versionedHome, "run"))
}

func assertAgentInstallCleaned(t *testing.T, versionedHome string, agentExecutableName string) {
	assert.DirExists(t, versionedHome)
	assert.DirExists(t, filepath.Join(versionedHome, "logs"))
	assert.NoDirExists(t, filepath.Join(versionedHome, "run"))
	assert.NoFileExists(t, paths.BinaryPath(versionedHome, agentExecutableName))
}

// checkFilesAfterCleanup is a convenience function to check the file structure within topDir.
// *AgentHome paths must be the expected old and new agent paths relative to topDir (typically in the form of "data/elastic-agent-*")
func checkFilesAfterCleanup(t *testing.T, topDir, newAgentHome string, oldAgentHomes ...string) {
	t.Helper()
	// the old agent directories must not exist anymore
	for _, oldAgentHome := range oldAgentHomes {
		assert.NoDirExistsf(t, filepath.Join(topDir, oldAgentHome), "old agent directory %q should be deleted after cleanup", oldAgentHome)
	}

	// check the new agent home
	assert.DirExists(t, filepath.Join(topDir, newAgentHome), "new agent directory should exist after cleanup")
	agentExecutable := AgentName
	if runtime.GOOS == "windows" {
		agentExecutable += ".exe"
	}
	symlinkPath := filepath.Join(topDir, agentExecutable)
	linkTarget, err := os.Readlink(symlinkPath)
	if assert.NoError(t, err, "unable to read symbolic link") {
		assert.Equal(t, paths.BinaryPath(newAgentHome, agentExecutable), linkTarget, "symbolic link should point to the new agent executable after cleanup")
	}

	// read the elastic agent placeholder via the symlink
	elasticAgentBytes, err := os.ReadFile(symlinkPath)
	if assert.NoError(t, err, "error reading elastic-agent content through the symlink") {
		assert.Equal(t, []byte("Placeholder for agent 4.5.6-SNAPSHOT"), elasticAgentBytes, "reading elastic-agent content through symbolic link should point to the new version")
	}

	assert.NoFileExists(t, filepath.Join(topDir, "data", markerFilename), "update marker should have been cleaned up")
}

// checkFilesAfterRollback is a convenience function to check the file structure within topDir.
// *AgentHome paths must be the expected old and new agent paths relative to topDir (typically in the form of "data/elastic-agent-*")
func checkFilesAfterRollback(t *testing.T, topDir, oldAgentHome, newAgentHome string) {
	t.Helper()
	// the new agent directory must still exist (for the logs)
	assert.DirExists(t, filepath.Join(topDir, newAgentHome), "new agent directory should still exist after rollback")
	assert.DirExists(t, filepath.Join(topDir, newAgentHome, "logs"), "new agent logs directory should still exist after rollback")
	// some things should have been removed from the new agent directory
	assert.NoDirExists(t, filepath.Join(topDir, newAgentHome, "components"), "new agent components directory should have been cleaned up in the rollback")
	assert.NoDirExists(t, filepath.Join(topDir, newAgentHome, "run"), "new agent run directory should have been cleaned up in the rollback")
	assert.NoFileExists(t, filepath.Join(topDir, newAgentHome, AgentName), "new agent binary should have been cleaned up in the rollback")

	// check the old agent home
	assert.DirExists(t, filepath.Join(topDir, oldAgentHome), "old agent directory should exist after rollback")
	agentExecutable := AgentName
	if runtime.GOOS == "windows" {
		agentExecutable += ".exe"
	}
	symlinkPath := filepath.Join(topDir, agentExecutable)
	linkTarget, err := os.Readlink(symlinkPath)
	if assert.NoError(t, err, "unable to read symbolic link") {
		// Due to the unique way the rollback process works we end up with an absolute path in the link
		expectedLinkTargetAfterRollback := paths.BinaryPath(filepath.Join(topDir, oldAgentHome), agentExecutable)
		assert.Equal(t, expectedLinkTargetAfterRollback, linkTarget, "symbolic link should point to the old agent executable after rollback")
	}

	// read the elastic agent placeholder via the symlink
	elasticAgentBytes, err := os.ReadFile(symlinkPath)
	if assert.NoError(t, err, "error reading elastic-agent content through the symlink") {
		assert.Equal(t, []byte("Placeholder for agent 1.2.3-SNAPSHOT"), elasticAgentBytes, "reading elastic-agent content through symbolic link should point to the old version")
	}

	assert.FileExists(t, filepath.Join(topDir, "data", markerFilename), "update marker should survive cleanup in case of rollback")
}

// setupAgents create fake agent installs, update marker file and symlink pointing to one of the installations' elastic-agent placeholder
func setupAgents(t *testing.T, log *logger.Logger, topDir string, installations setupAgentInstallations, writeUpdateMarker bool) {

	var (
		oldAgentVersion       testAgentVersion
		oldAgentVersionedHome string
		newAgentVersion       testAgentVersion
		newAgentVersionedHome string
		useNewMarker          bool
	)
	for _, ia := range installations.installedAgents {
		versionedHome := createFakeAgentInstall(t, topDir, ia.version.version, ia.version.hash, ia.useVersionInPath)
		t.Logf("Created fake agent install for %+v located at %q", ia, versionedHome)
		if installations.upgradeFrom == ia.version {
			t.Logf("Setting version %+v as FROM version for the update marker", ia.version)
			oldAgentVersion = ia.version
			oldAgentVersionedHome = versionedHome
		}

		if installations.upgradeTo == ia.version {
			t.Logf("Setting version %+v as TO version for the update marker", ia.version)
			newAgentVersion = ia.version
			newAgentVersionedHome = versionedHome
			useNewMarker = ia.useVersionInPath
		}

		if installations.currentAgent == ia.version {
			t.Logf("Creating symlink pointing to %q", versionedHome)
			createLink(t, topDir, versionedHome)
		}
	}

	if writeUpdateMarker {
		t.Logf("Creating upgrade marker from %+v located at %q to %+v located at %q", oldAgentVersion, oldAgentVersionedHome, newAgentVersion, newAgentVersionedHome)
		createUpdateMarker(t, log, topDir, newAgentVersion.version, newAgentVersion.hash, newAgentVersionedHome, oldAgentVersion.version, oldAgentVersion.hash, oldAgentVersionedHome, useNewMarker)
	}

}

// createFakeAgentInstall will create a mock agent install within topDir, possibly using the version in the directory name, depending on useVersionInPath
// it MUST return the path to the created versionedHome relative to topDir, to mirror what step_unpack returns
func createFakeAgentInstall(t *testing.T, topDir, version, hash string, useVersionInPath bool) string {

	// create versioned home
	versionedHome := fmt.Sprintf("elastic-agent-%s", hash[:HashLen])
	if useVersionInPath {
		// use the version passed as parameter
		versionedHome = fmt.Sprintf("elastic-agent-%s-%s", version, hash[:HashLen])
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
	agentExecutableName := AgentName
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

func createLink(t *testing.T, topDir string, currentAgentVersionedHome string) {
	linkTarget := paths.BinaryPath(currentAgentVersionedHome, AgentName)
	linkName := AgentName
	if runtime.GOOS == "windows" {
		linkTarget += ".exe"
		linkName += ".exe"
	}
	err := os.Symlink(linkTarget, filepath.Join(topDir, linkName))
	require.NoError(t, err, "error creating test symlink to fake agent install")
}

func createUpdateMarker(t *testing.T, log *logger.Logger, topDir, newAgentVersion, newAgentHash, newAgentVersionedHome, oldAgentVersion, oldAgentHash, oldAgentVersionedHome string, useNewMarker bool) {

	if !useNewMarker {
		newAgentVersion = ""
		newAgentVersionedHome = ""
		oldAgentVersionedHome = ""
	}

	newAgentInstall := agentInstall{
		version:       newAgentVersion,
		hash:          newAgentHash,
		versionedHome: newAgentVersionedHome,
	}
	oldAgentInstall := agentInstall{
		version:       oldAgentVersion,
		hash:          oldAgentHash,
		versionedHome: oldAgentVersionedHome,
	}

	// use a rollback window value that disables the creation of the available_rollbacks field in the upgrade marker
	// to create a backward compatible marker
	markUpgrade := markUpgradeProvider(UpdateActiveCommit, os.WriteFile)
	err := markUpgrade(log,
		paths.DataFrom(topDir),
		time.Now(),
		newAgentInstall,
		oldAgentInstall,
		nil, nil, nil)
	require.NoError(t, err, "error writing fake update marker")
}

// TestRollbackWithOpts_PreservesUnexpiredRollbacksAvailable verifies that an unexpired
// entry in marker.RollbacksAvailable survives a rollback even when a different target
// is chosen, so that it remains available for a subsequent rollback attempt.
//
// Setup:
//   - Three on-disk installs A, B, C.
//   - Symlink points at C (the failing upgrade).
//   - Update marker records C as new, A as previous, with both A and B listed
//     in RollbacksAvailable with future TTLs.
//
// We roll back to A. B (also unexpired) must survive
func TestRollbackWithOpts_PreservesUnexpiredRollbacksAvailable(t *testing.T) {
	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	versionA := testAgentVersion{version: "1.0.0", hash: "aaaaaa"}
	versionB := testAgentVersion{version: "2.0.0", hash: "bbbbbb"}
	versionC := testAgentVersion{version: "3.0.0", hash: "cccccc"}

	testLogger, _ := loggertest.New(t.Name())
	testTop := t.TempDir()

	relA := createFakeAgentInstall(t, testTop, versionA.version, versionA.hash, true)
	relB := createFakeAgentInstall(t, testTop, versionB.version, versionB.hash, true)
	relC := createFakeAgentInstall(t, testTop, versionC.version, versionC.hash, true)

	createLink(t, testTop, relC)

	validUntil := time.Now().Add(24 * time.Hour)
	availableRollbacks := map[string]ttl.TTLMarker{
		relA: {Version: versionA.version, Hash: versionA.hash, ValidUntil: validUntil},
		relB: {Version: versionB.version, Hash: versionB.hash, ValidUntil: validUntil},
	}

	require.NoError(t,
		ttl.NewTTLMarkerRegistry(testLogger, testTop).Set(availableRollbacks),
		"writing TTL registry with two valid entries")

	markUpgrade := markUpgradeProvider(UpdateActiveCommit, os.WriteFile)
	err := markUpgrade(
		testLogger,
		paths.DataFrom(testTop),
		time.Now(),
		agentInstall{version: versionC.version, hash: versionC.hash, versionedHome: relC},
		agentInstall{version: versionA.version, hash: versionA.hash, versionedHome: relA},
		nil, nil, availableRollbacks,
	)
	require.NoError(t, err, "writing update marker with two RollbacksAvailable entries")

	mockClient := client.NewMockClient(t)
	mockClient.EXPECT().Connect(
		mock.AnythingOfType("*context.timerCtx"),
		mock.AnythingOfType("*grpc.funcDialOption"),
		mock.AnythingOfType("*grpc.funcDialOption"),
	).Return(nil)
	mockClient.EXPECT().Disconnect().Return()
	mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

	err = RollbackWithOpts(t.Context(), testLogger, mockClient, testTop, relA, versionA.hash)
	require.NoError(t, err, "RollbackWithOpts to A")

	t.Run("rollback target A is preserved", func(t *testing.T) {
		assertAgentInstallExists(t, filepath.Join(testTop, relA), agentExecutableName)
	})

	t.Run("failing upgrade C is cleaned up", func(t *testing.T) {
		assertAgentInstallCleaned(t, filepath.Join(testTop, relC), agentExecutableName)
	})

	t.Run("other in-TTL rollback target B is preserved", func(t *testing.T) {
		// B's directory must survive — its TTL has not expired and the live
		// TTL registry still lists it as a valid rollback target.
		assertAgentInstallExists(t, filepath.Join(testTop, relB), agentExecutableName)
	})
}

// TestRollbackWithOpts_RemovesMalformedTTLRollbacksAvailable verifies that a
// directory whose .ttl marker is corrupt is NOT preserved by post-rollback
// cleanup. Under the registry contract a parseable TTL is the only proof an
// install is a valid rollback target, so a malformed entry is treated like a
// missing one. This preserves the self-healing property that a corrupt .ttl
// outside the active install gets reaped at the next rollback, allowing
// future upgrades to proceed against a clean registry.
func TestRollbackWithOpts_RemovesMalformedTTLRollbacksAvailable(t *testing.T) {
	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	versionA := testAgentVersion{version: "1.0.0", hash: "aaaaaa"}
	versionB := testAgentVersion{version: "2.0.0", hash: "bbbbbb"}
	versionC := testAgentVersion{version: "3.0.0", hash: "cccccc"}

	testLogger, _ := loggertest.New(t.Name())
	testTop := t.TempDir()

	relA := createFakeAgentInstall(t, testTop, versionA.version, versionA.hash, true)
	relB := createFakeAgentInstall(t, testTop, versionB.version, versionB.hash, true)
	relC := createFakeAgentInstall(t, testTop, versionC.version, versionC.hash, true)

	createLink(t, testTop, relC)

	// A has a valid in-TTL marker; B has a corrupt one (unparseable YAML).
	// Both directories must survive the rollback to A.
	now := time.Now()
	availableRollbacks := map[string]ttl.TTLMarker{
		relA: {Version: versionA.version, Hash: versionA.hash, ValidUntil: now.Add(24 * time.Hour)},
	}
	require.NoError(t,
		ttl.NewTTLMarkerRegistry(testLogger, testTop).Set(availableRollbacks),
		"writing TTL registry with single valid entry")
	require.NoError(t,
		os.WriteFile(filepath.Join(testTop, relB, ".ttl"), []byte("this is not yaml"), 0644),
		"writing corrupt .ttl for B")

	markUpgrade := markUpgradeProvider(UpdateActiveCommit, os.WriteFile)
	err := markUpgrade(
		testLogger,
		paths.DataFrom(testTop),
		now,
		agentInstall{version: versionC.version, hash: versionC.hash, versionedHome: relC},
		agentInstall{version: versionA.version, hash: versionA.hash, versionedHome: relA},
		nil, nil, availableRollbacks,
	)
	require.NoError(t, err, "writing update marker")

	mockClient := client.NewMockClient(t)
	mockClient.EXPECT().Connect(
		mock.AnythingOfType("*context.timerCtx"),
		mock.AnythingOfType("*grpc.funcDialOption"),
		mock.AnythingOfType("*grpc.funcDialOption"),
	).Return(nil)
	mockClient.EXPECT().Disconnect().Return()
	mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

	err = RollbackWithOpts(t.Context(), testLogger, mockClient, testTop, relA, versionA.hash)
	require.NoError(t, err, "RollbackWithOpts to A")

	t.Run("rollback target A is preserved", func(t *testing.T) {
		assertAgentInstallExists(t, filepath.Join(testTop, relA), agentExecutableName)
	})

	t.Run("failing upgrade C is cleaned up", func(t *testing.T) {
		assertAgentInstallCleaned(t, filepath.Join(testTop, relC), agentExecutableName)
	})

	t.Run("install B with corrupt .ttl is cleaned up", func(t *testing.T) {
		// B's .ttl is unparseable, so we cannot prove B is a valid rollback
		// target. Treat it like a directory with no .ttl and let cleanup
		// reap it — that's the self-healing path that lets the next upgrade
		// proceed against a clean registry.
		assertAgentInstallCleaned(t, filepath.Join(testTop, relB), agentExecutableName)
	})
}

// TestRollbackWithOpts_RemovesExpiredRollbacksAvailable verifies that expired
// entries in marker.RollbacksAvailable are not preserved by the rollback
// cleanup: the keep list is filtered by ValidUntil so expired directories get
// swept alongside the failing upgrade target.
func TestRollbackWithOpts_RemovesExpiredRollbacksAvailable(t *testing.T) {
	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	versionA := testAgentVersion{version: "1.0.0", hash: "aaaaaa"}
	versionB := testAgentVersion{version: "2.0.0", hash: "bbbbbb"}
	versionC := testAgentVersion{version: "3.0.0", hash: "cccccc"}

	testLogger, _ := loggertest.New(t.Name())
	testTop := t.TempDir()

	relA := createFakeAgentInstall(t, testTop, versionA.version, versionA.hash, true)
	relB := createFakeAgentInstall(t, testTop, versionB.version, versionB.hash, true)
	relC := createFakeAgentInstall(t, testTop, versionC.version, versionC.hash, true)

	createLink(t, testTop, relC)

	now := time.Now()
	availableRollbacks := map[string]ttl.TTLMarker{
		relA: {Version: versionA.version, Hash: versionA.hash, ValidUntil: now.Add(24 * time.Hour)},
		relB: {Version: versionB.version, Hash: versionB.hash, ValidUntil: now.Add(-1 * time.Hour)},
	}

	require.NoError(t,
		ttl.NewTTLMarkerRegistry(testLogger, testTop).Set(availableRollbacks),
		"writing TTL registry with mixed-TTL entries")

	markUpgrade := markUpgradeProvider(UpdateActiveCommit, os.WriteFile)
	err := markUpgrade(
		testLogger,
		paths.DataFrom(testTop),
		now,
		agentInstall{version: versionC.version, hash: versionC.hash, versionedHome: relC},
		agentInstall{version: versionA.version, hash: versionA.hash, versionedHome: relA},
		nil, nil, availableRollbacks,
	)
	require.NoError(t, err, "writing update marker with mixed TTL RollbacksAvailable entries")

	mockClient := client.NewMockClient(t)
	mockClient.EXPECT().Connect(
		mock.AnythingOfType("*context.timerCtx"),
		mock.AnythingOfType("*grpc.funcDialOption"),
		mock.AnythingOfType("*grpc.funcDialOption"),
	).Return(nil)
	mockClient.EXPECT().Disconnect().Return()
	mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

	err = RollbackWithOpts(t.Context(), testLogger, mockClient, testTop, relA, versionA.hash)
	require.NoError(t, err, "RollbackWithOpts to A")

	t.Run("rollback target A is preserved", func(t *testing.T) {
		assertAgentInstallExists(t, filepath.Join(testTop, relA), agentExecutableName)
	})

	t.Run("failing upgrade C is cleaned up", func(t *testing.T) {
		assertAgentInstallCleaned(t, filepath.Join(testTop, relC), agentExecutableName)
	})

	t.Run("expired rollback target B is cleaned up", func(t *testing.T) {
		assertAgentInstallCleaned(t, filepath.Join(testTop, relB), agentExecutableName)
	})
}

// TestLiveVersionedHome exercises the helper against a real install layout for
// the host OS. createFakeAgentInstall + createLink build the on-disk structure
// using paths.BinaryPath, so on darwin CI this is a real darwin test (the
// .app/Contents/MacOS bundle is created and resolved); on linux/windows CI it
// covers the flat layout. If paths.BinaryPath ever changes its layout on a
// platform without a corresponding update to liveVersionedHome, this test will
// fail on that platform's CI.
func TestLiveVersionedHome(t *testing.T) {
	t.Run("symlink points at versioned-home binary", func(t *testing.T) {
		topDir := t.TempDir()
		versionedHome := createFakeAgentInstall(t, topDir, "1.2.3", "abcdef", true)
		createLink(t, topDir, versionedHome)

		got, err := liveVersionedHome(topDir)
		require.NoError(t, err)
		expected, err := filepath.Rel(topDir, filepath.Join(topDir, versionedHome))
		require.NoError(t, err)
		require.Equal(t, expected, got)
	})

	t.Run("missing symlink returns error", func(t *testing.T) {
		topDir := t.TempDir()
		_, err := liveVersionedHome(topDir)
		require.Error(t, err)
	})

	t.Run("symlink resolving outside topDir returns error", func(t *testing.T) {
		topDir := t.TempDir()
		// Place the binary in a separate temp dir so the symlink resolves
		// outside topDir. liveVersionedHome must reject the result rather
		// than returning a "../<other>" relative path that would let cleanup
		// reason about a directory it doesn't own.
		outsideDir := t.TempDir()
		binary := filepath.Join(outsideDir, AgentName)
		require.NoError(t, os.WriteFile(binary, nil, 0o755))
		require.NoError(t, os.Symlink(binary, filepath.Join(topDir, AgentName)))

		_, err := liveVersionedHome(topDir)
		require.Error(t, err)
	})
}

// TestCleanup_DegradesGracefullyWhenLiveHomeUnresolvable encodes the
// graceful-degradation contract: when the symlink cannot be resolved, cleanup
// must still proceed (sweeping directories that the parsed TTL marks as
// removable) but flag the run as degraded via errCleanupDegraded. The upgrade
// marker is preserved so that the next run can revisit cleanup with full
// verification.
func TestCleanup_DegradesGracefullyWhenLiveHomeUnresolvable(t *testing.T) {
	t.Run("removeMarker=false: degraded error returned, expired TTL swept, orphan kept", func(t *testing.T) {
		testLogger, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		// Two installs:
		// - expired: has an expired TTL, no symlink target -> should be swept
		// - orphan : has no TTL, no symlink target          -> must be kept
		expiredHome := createFakeAgentInstall(t, topDir, "1.2.3", "expire", true)
		orphanHome := createFakeAgentInstall(t, topDir, "4.5.6", "orphan", true)
		now := time.Now()
		require.NoError(t,
			ttl.NewTTLMarkerRegistry(testLogger, topDir).Set(map[string]ttl.TTLMarker{
				expiredHome: {Version: "1.2.3", Hash: "expire", ValidUntil: now.Add(-1 * time.Hour)},
			}),
			"writing TTL registry with expired entry")

		// No symlink.

		err := cleanup(testLogger, topDir, false, false, 0)
		require.Error(t, err)
		require.ErrorIs(t, err, errCleanupDegraded)

		// Expired TTL is swept even when the symlink is unresolvable.
		assert.NoDirExists(t, filepath.Join(topDir, expiredHome),
			"expired TTL entry should be swept even when symlink is unresolvable")
		// Orphan is preserved because we cannot verify it isn't the live install.
		assert.DirExists(t, filepath.Join(topDir, orphanHome),
			"orphan must be preserved when symlink is unresolvable")
	})

	t.Run("removeMarker=true: marker survives because verification was degraded", func(t *testing.T) {
		testLogger, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		require.NoError(t, os.MkdirAll(paths.DataFrom(topDir), 0o750))
		markerPath := filepath.Join(paths.DataFrom(topDir), markerFilename)
		require.NoError(t,
			SaveMarker(paths.DataFrom(topDir), &UpdateMarker{Version: "1.2.3", Hash: "deadbeef"}, true),
			"writing valid upgrade marker fixture")

		err := cleanup(testLogger, topDir, true, false, 0)
		require.Error(t, err)
		require.ErrorIs(t, err, errCleanupDegraded)

		assert.FileExists(t, markerPath,
			"upgrade marker must survive a degraded cleanup so the next run can verify with full info")
	})
}

// TestCleanAvailableRollbacks_DegradesGracefullyWhenSymlinkUnresolvable
// verifies that CleanAvailableRollbacks proceeds with degraded verification
// when the agent symlink cannot be resolved: expired TTL entries are swept,
// orphans are kept conservatively, unexpired TTL entries are returned, and
// the error wraps errCleanupDegraded.
func TestCleanAvailableRollbacks_DegradesGracefullyWhenSymlinkUnresolvable(t *testing.T) {
	testLogger, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	versionA := testAgentVersion{version: "1.0.0", hash: "aaaaaa"} // unexpired TTL -> keep
	versionB := testAgentVersion{version: "2.0.0", hash: "bbbbbb"} // caller-protected
	versionC := testAgentVersion{version: "3.0.0", hash: "cccccc"} // expired TTL -> sweep
	versionD := testAgentVersion{version: "4.0.0", hash: "dddddd"} // orphan -> keep

	relA := createFakeAgentInstall(t, topDir, versionA.version, versionA.hash, true)
	relB := createFakeAgentInstall(t, topDir, versionB.version, versionB.hash, true)
	relC := createFakeAgentInstall(t, topDir, versionC.version, versionC.hash, true)
	relD := createFakeAgentInstall(t, topDir, versionD.version, versionD.hash, true)

	// No symlink.

	now := time.Now()
	validUntil := now.Add(24 * time.Hour)
	availableRollbacks := map[string]ttl.TTLMarker{
		relA: {Version: versionA.version, Hash: versionA.hash, ValidUntil: validUntil},
		relC: {Version: versionC.version, Hash: versionC.hash, ValidUntil: now.Add(-1 * time.Hour)},
	}
	registry := ttl.NewTTLMarkerRegistry(testLogger, topDir)
	require.NoError(t, registry.Set(availableRollbacks), "writing TTL registry")

	leftover, err := CleanAvailableRollbacks(testLogger, registry, topDir, relB, now, CleanupExpiredRollbacks)

	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded,
		"symlink-unresolvable cleanup must return errCleanupDegraded")
	if assert.Len(t, leftover, 1, "unexpired rollback must be returned for future cleanup") {
		m := leftover[relA]
		assert.Equal(t, versionA.version, m.Version)
		assert.Equal(t, versionA.hash, m.Hash)
		assert.WithinDuration(t, validUntil, m.ValidUntil, time.Second,
			"ValidUntil should round-trip cleanly (monotonic clock stripped by YAML)")
	}

	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}
	// Unexpired TTL — keep.
	assertAgentInstallExists(t, filepath.Join(topDir, relA), agentExecutableName)
	// Caller-protected — keep.
	assertAgentInstallExists(t, filepath.Join(topDir, relB), agentExecutableName)
	// Expired TTL — swept even though symlink is unresolvable.
	assert.NoDirExists(t, filepath.Join(topDir, relC),
		"expired TTL entry should be swept even when symlink is unresolvable")
	// Orphan — kept because we cannot prove it is not the live install.
	assertAgentInstallExists(t, filepath.Join(topDir, relD), agentExecutableName)
}

// TestCleanAvailableRollbacks_NilDetailsMarker_LenientMode verifies that
// CleanAvailableRollbacks (requireMarkerDetails=false, lenient) preserves both
// installs referenced by a nil-Details upgrade marker.
//
// This is the counterpart to TestCleanup_NilDetailsMarker_StrictMode: legacy agents
// that did not populate marker Details must still have their installs protected during
// the periodic cleanup window, so a rollback remains possible.
func TestCleanAvailableRollbacks_NilDetailsMarker_LenientMode(t *testing.T) {
	testLogger, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	currentVersionedHome := createFakeAgentInstall(t, topDir, "9.0.0", "newver0000", true)
	prevVersionedHome := createFakeAgentInstall(t, topDir, "8.0.0", "oldver0000", true)
	createLink(t, topDir, currentVersionedHome)

	require.NoError(t, os.MkdirAll(paths.DataFrom(topDir), 0o750))
	require.NoError(t, SaveMarker(paths.DataFrom(topDir), &UpdateMarker{
		Version:           "9.0.0",
		Hash:              "newver",
		VersionedHome:     currentVersionedHome,
		PrevVersion:       "8.0.0",
		PrevHash:          "oldver",
		PrevVersionedHome: prevVersionedHome,
		Details:           nil, // legacy marker without upgrade details
	}, true), "writing nil-Details upgrade marker fixture")

	source := ttl.NewTTLMarkerRegistry(testLogger, topDir)

	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	_, err := CleanAvailableRollbacks(testLogger, source, topDir, currentVersionedHome, time.Now(), CleanupExpiredRollbacks)
	require.NoError(t, err)

	// currentVersionedHome is caller-protected.
	assertAgentInstallExists(t, filepath.Join(topDir, currentVersionedHome), agentExecutableName)

	// prevVersionedHome: referenced by a nil-Details marker; in lenient mode this must protect it.
	assertAgentInstallExists(t, filepath.Join(topDir, prevVersionedHome), agentExecutableName)
}

// TestCleanup_NilDetailsMarker_StrictMode verifies the interaction between
// requireMarkerDetails=true (used by Cleanup after rollback) and callerProtected.
//
// A nil-Details upgrade marker (written by a legacy agent that did not populate
// details) must NOT protect directories from removal in strict mode, BUT
// callerProtected entries must still survive regardless.
//
// Scenario (post-rollback):
//   - prevVersionedHome: the rollback target, explicitly protected by Cleanup's keep list
//   - newVersionedHome:  the failed upgrade directory, NOT protected
//   - marker: nil Details, references both
//
// Expected:
//   - prevVersionedHome kept   (callerProtected wins over everything)
//   - newVersionedHome removed (nil-Details + not callerProtected + not TTL)
func TestCleanup_NilDetailsMarker_StrictMode(t *testing.T) {
	testLogger, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	newVersionedHome := createFakeAgentInstall(t, topDir, "9.0.0", "newver0000", true)
	prevVersionedHome := createFakeAgentInstall(t, topDir, "8.0.0", "oldver0000", true)
	// After rollback the symlink points at the previous (restored) install.
	createLink(t, topDir, prevVersionedHome)

	// Write a nil-Details upgrade marker referencing both installs.
	// Passing nil for details simulates a marker written by a pre-Details agent version.
	require.NoError(t, os.MkdirAll(paths.DataFrom(topDir), 0o750))
	require.NoError(t, SaveMarker(paths.DataFrom(topDir), &UpdateMarker{
		Version:           "9.0.0",
		Hash:              "newver",
		VersionedHome:     newVersionedHome,
		PrevVersion:       "8.0.0",
		PrevHash:          "oldver",
		PrevVersionedHome: prevVersionedHome,
		Details:           nil, // nil Details = legacy marker without upgrade details
	}, true), "writing nil-Details upgrade marker fixture")

	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}

	// Cleanup is called after rollback with prevVersionedHome as the keep target.
	// requireMarkerDetails=true (strict) is used internally by cleanup().
	err := cleanup(testLogger, topDir, false, false, 0, prevVersionedHome)
	require.NoError(t, err)

	// prevVersionedHome is in callerProtected — must survive even though the nil-Details
	// marker cannot protect it in strict mode.
	assertAgentInstallExists(t, filepath.Join(topDir, prevVersionedHome), agentExecutableName)

	// newVersionedHome: not callerProtected, no TTL, nil-Details in strict mode → fully removed.
	assert.NoDirExists(t, filepath.Join(topDir, newVersionedHome),
		"failed upgrade directory must be removed when marker has nil Details in strict mode")
}
