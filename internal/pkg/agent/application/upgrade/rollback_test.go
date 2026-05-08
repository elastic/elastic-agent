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

// TestRollbackWithOpts_PreservesInTTLRollbacksAvailable encodes the
// multi-rollback retention contract for RollbackWithOpts: in-TTL entries in
// marker.RollbacksAvailable must survive a rollback regardless of which one is
// chosen as the rollback target.
//
// Setup:
//   - Three on-disk installs A, B, C.
//   - Symlink points at C (the failing upgrade).
//   - Update marker records C as new, A as previous, with both A and B listed
//     in RollbacksAvailable with future TTLs.
//
// We roll back to A. B (also unexpired) must survive
func TestRollbackWithOpts_PreservesInTTLRollbacksAvailable(t *testing.T) {
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
