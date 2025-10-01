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
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
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
				if assert.Len(t, snippetLogs, 1) {
					assert.Equal(t, zapcore.WarnLevel, snippetLogs[0].Level)
				}
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
