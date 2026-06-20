// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

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
			setupAgents(t, testLogger, testTop, tt.agentInstallsSetup)
			if tt.additionalSetup != nil {
				tt.additionalSetup(t, testTop)
			}
			marker, err := LoadMarker(paths.DataFrom(testTop))
			require.NoError(t, err, "error loading update marker")
			require.NotNil(t, marker, "loaded marker must not be nil")
			t.Logf("Loaded update marker %+v", marker)
			tt.wantErr(t, cleanup(testLogger, testTop, marker.VersionedHome, marker.Hash, tt.args.removeMarker, tt.args.keepLogs, 0), fmt.Sprintf("Cleanup(%v, %v, %v, %v)", marker.VersionedHome, marker.Hash, tt.args.removeMarker, tt.args.keepLogs))
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
	err := cleanup(testLogger, topDir, otherHome, "", false, false, 0)
	require.NoError(t, err)

	// Both installs must remain: otherHome because it's in the keep list,
	// liveHome because the symlink-based guard added it.
	assert.DirExists(t, filepath.Join(topDir, liveHome),
		"live versioned home must be preserved by the cleanup guard")
	assert.DirExists(t, filepath.Join(topDir, otherHome))
}

// TestCleanup_DropsPhantomKeepListEntry ensures cleanup() drops keep-list
// entries that don't exist on disk so the "Keeping" log line truthfully
// reflects what is being preserved. The dropped entry must be reported via
// an Info log so triage can see why a stale marker.VersionedHome is gone.
func TestCleanup_DropsPhantomKeepListEntry(t *testing.T) {
	testLogger, obs := loggertest.New(t.Name())
	topDir := t.TempDir()

	// One real install + symlink, plus a phantom path the caller insists on.
	liveHome := createFakeAgentInstall(t, topDir, version123Snapshot.version, version123Snapshot.hash, true)
	createLink(t, topDir, liveHome)
	phantomHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-deadbeef")

	err := cleanup(testLogger, topDir, phantomHome, "", false, false, 0)
	require.NoError(t, err)

	// Live install is still present (cleanup guard kicked in).
	assert.DirExists(t, filepath.Join(topDir, liveHome))

	// Phantom entry was reported as dropped.
	dropLogs := obs.FilterMessageSnippet("dropping non-existent keep-list entry").All()
	assert.Len(t, dropLogs, 1, "expected exactly one drop log entry")

	// "Keeping" log line must NOT mention the phantom entry.
	keepLogs := obs.FilterMessageSnippet("Starting cleanup of versioned homes. Keeping:").All()
	if assert.Len(t, keepLogs, 1) {
		assert.NotContains(t, keepLogs[0].Message, "deadbeef",
			"keep-list log must not contain phantom entry")
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
			setupAgents(t, testLogger, testTop, tt.agentInstallsSetup)
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
	agentExecutable := agentName
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
	assert.NoFileExists(t, filepath.Join(topDir, newAgentHome, agentName), "new agent binary should have been cleaned up in the rollback")

	// check the old agent home
	assert.DirExists(t, filepath.Join(topDir, oldAgentHome), "old agent directory should exist after rollback")
	agentExecutable := agentName
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

	assert.NoFileExists(t, filepath.Join(topDir, "data", markerFilename), "update marker should have been cleaned up")
}

// setupAgents create fake agent installs, update marker file and symlink pointing to one of the installations' elastic-agent placeholder
func setupAgents(t *testing.T, log *logger.Logger, topDir string, installations setupAgentInstallations) {

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

	t.Logf("Creating upgrade marker from %+v located at %q to %+v located at %q", oldAgentVersion, oldAgentVersionedHome, newAgentVersion, newAgentVersionedHome)
	createUpdateMarker(t, log, topDir, newAgentVersion.version, newAgentVersion.hash, newAgentVersionedHome, oldAgentVersion.version, oldAgentVersion.hash, oldAgentVersionedHome, useNewMarker)
}

// createFakeAgentInstall will create a mock agent install within topDir, possibly using the version in the directory name, depending on useVersionInPath
// it MUST return the path to the created versionedHome relative to topDir, to mirror what step_unpack returns
func createFakeAgentInstall(t *testing.T, topDir, version, hash string, useVersionInPath bool) string {

	// create versioned home
	versionedHome := fmt.Sprintf("elastic-agent-%s", hash[:hashLen])
	if useVersionInPath {
		// use the version passed as parameter
		versionedHome = fmt.Sprintf("elastic-agent-%s-%s", version, hash[:hashLen])
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
	agentExecutableName := agentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}
	err = os.WriteFile(paths.BinaryPath(absVersionedHomePath, agentExecutableName), []byte(fmt.Sprintf("Placeholder for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing elastic agent binary placeholder %q", agentExecutableName)
	err = os.WriteFile(filepath.Join(absLogsDirPath, "fakelog.ndjson"), []byte(fmt.Sprintf("Sample logs for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing fake log placeholder %q")

	// return the path relative to top exactly like the step_unpack does
	return relVersionedHomePath
}

func createLink(t *testing.T, topDir string, currentAgentVersionedHome string) {
	linkTarget := paths.BinaryPath(currentAgentVersionedHome, agentName)
	linkName := agentName
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

	markUpgrade := markUpgradeProvider(UpdateActiveCommit, os.WriteFile)
	err := markUpgrade(log,
		paths.DataFrom(topDir),
		newAgentInstall,
		oldAgentInstall,
		nil, nil)
	require.NoError(t, err, "error writing fake update marker")
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
		binary := filepath.Join(outsideDir, agentName)
		require.NoError(t, os.WriteFile(binary, nil, 0o755))
		require.NoError(t, os.Symlink(binary, filepath.Join(topDir, agentName)))

		_, err := liveVersionedHome(topDir)
		require.Error(t, err)
	})
}

// TestCleanup_AbortsWhenLiveHomeUnresolvable encodes the
// refusal-to-proceed contract: when the symlink cannot be resolved, cleanup
// must return an error and leave the on-disk state untouched rather than risk
// deleting the live install based on a stale keep list. The resolve runs
// before any destructive op so neither the versioned home nor the upgrade
// marker may be mutated when the abort fires.
func TestCleanup_AbortsWhenLiveHomeUnresolvable(t *testing.T) {
	t.Run("removeMarker=false: error returned and versioned home untouched", func(t *testing.T) {
		testLogger, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		phantomHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-deadbeef")
		err := cleanup(testLogger, topDir, phantomHome, "", false, false, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot identify live versioned home")
	})

	t.Run("removeMarker=true: marker survives because resolve precedes CleanMarker", func(t *testing.T) {
		testLogger, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		require.NoError(t, os.MkdirAll(paths.DataFrom(topDir), 0o750))
		markerPath := filepath.Join(paths.DataFrom(topDir), markerFilename)
		require.NoError(t, os.WriteFile(markerPath, []byte("placeholder upgrade marker"), 0o600),
			"writing placeholder marker file")

		phantomHome := filepath.Join("data", "elastic-agent-1.2.3-SNAPSHOT-deadbeef")
		err := cleanup(testLogger, topDir, phantomHome, "", true, false, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot identify live versioned home")

		assert.FileExists(t, markerPath,
			"upgrade marker must survive an aborted cleanup (CleanMarker must not run before resolve)")
	})
}
