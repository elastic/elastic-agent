// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type hookFunc func(t *testing.T, topDir string)

type agentVersion struct {
	version string
	hash    string
}

type agentInstall struct {
	version          agentVersion
	useVersionInPath bool
}

type setupAgentInstallations struct {
	installedAgents []agentInstall
	upgradeFrom     agentVersion
	upgradeTo       agentVersion
	currentAgent    agentVersion
}

var (
	version123Snapshot = agentVersion{
		version: "1.2.3-SNAPSHOT",
		hash:    "abcdef",
	}
	version456Snapshot = agentVersion{
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

	tests := []struct {
		name               string
		args               args
		agentInstallsSetup setupAgentInstallations
		additionalSetup    hookFunc
		wantErr            assert.ErrorAssertionFunc
		checkAfterCleanup  hookFunc
	}{
		{
			name: "cleanup without versionedHome (legacy upgrade process)",
			args: args{
				currentVersionedHome: "data/elastic-agent-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []agentInstall{
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
				// the old agent directory must not exist anymore
				oldAgentHome := "elastic-agent-abcdef"
				assert.NoDirExists(t, filepath.Join(topDir, "data", oldAgentHome), "old agent directory should be deleted after cleanup")
				newAgentHome := "elastic-agent-ghijkl"
				assert.DirExists(t, filepath.Join(topDir, "data", newAgentHome), "new agent directory should exist after cleanup")
				agentExecutable := agentName
				if runtime.GOOS == "windows" {
					agentExecutable += ".exe"
				}
				symlinkPath := filepath.Join(topDir, agentExecutable)
				linkTarget, err := os.Readlink(symlinkPath)
				if assert.NoError(t, err, "unable to read symbolic link") {
					assert.Equal(t, filepath.Join("data", newAgentHome, agentExecutable), linkTarget, "symbolic link should point to the new agent executable after cleanup")
				}

				// read the elastic agent placeholder via the symlink
				elasticAgentBytes, err := os.ReadFile(symlinkPath)
				if assert.NoError(t, err, "error reading elastic-agent content through the symlink") {
					assert.Equal(t, []byte("Placeholder for agent 4.5.6-SNAPSHOT"), elasticAgentBytes, "reading elastic-agent content through symbolic link should point to the new version")
				}
			},
		},
		{
			name: "cleanup with versionedHome (new upgrade process)",
			args: args{
				currentVersionedHome: "data/elastic-agent-4.5.6-SNAPSHOT-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []agentInstall{
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
				// the old agent directory must not exist anymore
				oldAgentHome := "elastic-agent-1.2.3-SNAPSHOT-abcdef"
				assert.NoDirExists(t, filepath.Join(topDir, "data", oldAgentHome), "old agent directory should be deleted after cleanup")

				newAgentHome := "elastic-agent-4.5.6-SNAPSHOT-ghijkl"
				assert.DirExists(t, filepath.Join(topDir, "data", newAgentHome), "new agent directory should exist after cleanup")
				agentExecutable := agentName
				if runtime.GOOS == "windows" {
					agentExecutable += ".exe"
				}
				symlinkPath := filepath.Join(topDir, agentExecutable)
				linkTarget, err := os.Readlink(symlinkPath)
				if assert.NoError(t, err, "unable to read symbolic link") {
					assert.Equal(t, filepath.Join("data", newAgentHome, agentExecutable), linkTarget, "symbolic link should point to the new agent executable after cleanup")
				}

				// read the elastic agent placeholder via the symlink
				elasticAgentBytes, err := os.ReadFile(symlinkPath)
				if assert.NoError(t, err, "error reading elastic-agent content through the symlink") {
					assert.Equal(t, []byte("Placeholder for agent 4.5.6-SNAPSHOT"), elasticAgentBytes, "reading elastic-agent content through symbolic link should point to the new version")
				}
			},
		},
		{
			name: "cleanup with versionedHome only on the new agent (new upgrade process from an old agent upgraded with legacy process)",
			args: args{
				currentVersionedHome: "data/elastic-agent-4.5.6-SNAPSHOT-ghijkl",
				currentHash:          "ghijkl",
				removeMarker:         true,
				keepLogs:             false,
			},
			agentInstallsSetup: setupAgentInstallations{
				installedAgents: []agentInstall{
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
				// the old agent directory must not exist anymore
				oldAgentHome := "elastic-agent-abcdef"
				assert.NoDirExists(t, filepath.Join(topDir, "data", oldAgentHome), "old agent directory should be deleted after cleanup")

				newAgentHome := "elastic-agent-4.5.6-SNAPSHOT-ghijkl"
				assert.DirExists(t, filepath.Join(topDir, "data", newAgentHome), "new agent directory should exist after cleanup")
				agentExecutable := agentName
				if runtime.GOOS == "windows" {
					agentExecutable += ".exe"
				}
				symlinkPath := filepath.Join(topDir, agentExecutable)
				linkTarget, err := os.Readlink(symlinkPath)
				if assert.NoError(t, err, "unable to read symbolic link") {
					assert.Equal(t, filepath.Join("data", newAgentHome, agentExecutable), linkTarget, "symbolic link should point to the new agent executable after cleanup")
				}

				// read the elastic agent placeholder via the symlink
				elasticAgentBytes, err := os.ReadFile(symlinkPath)
				if assert.NoError(t, err, "error reading elastic-agent content through the symlink") {
					assert.Equal(t, []byte("Placeholder for agent 4.5.6-SNAPSHOT"), elasticAgentBytes, "reading elastic-agent content through symbolic link should point to the new version")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testTop := t.TempDir()
			setupAgents(t, testTop, tt.agentInstallsSetup)
			if tt.additionalSetup != nil {
				tt.additionalSetup(t, testTop)
			}
			testLogger, _ := logger.NewTesting(t.Name())
			tt.wantErr(t, Cleanup(testLogger, testTop, tt.args.currentVersionedHome, tt.args.currentHash, tt.args.removeMarker, tt.args.keepLogs), fmt.Sprintf("Cleanup(%v, %v, %v, %v)", tt.args.currentVersionedHome, tt.args.currentHash, tt.args.removeMarker, tt.args.keepLogs))
			tt.checkAfterCleanup(t, testTop)
		})
	}
}

func TestRollback(t *testing.T) {
	type args struct {
		ctx               context.Context
		log               *logger.Logger
		prevVersionedHome string
		prevHash          string
		currentHash       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, Rollback(tt.args.ctx, tt.args.log, tt.args.prevVersionedHome, tt.args.prevHash, tt.args.currentHash), fmt.Sprintf("Rollback(%v, %v, %v, %v, %v)", tt.args.ctx, tt.args.log, tt.args.prevVersionedHome, tt.args.prevHash, tt.args.currentHash))
		})
	}
}

func setupAgents(t *testing.T, topDir string, installations setupAgentInstallations) {

	var (
		oldAgentVersion       agentVersion
		oldAgentVersionedHome string
		newAgentVersion       agentVersion
		newAgentVersionedHome string
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
		}

		if installations.currentAgent == ia.version {
			t.Logf("Creating symlink pointing to %q", versionedHome)
			createLink(t, topDir, versionedHome)
		}
	}

	t.Logf("Creating upgrade marker from %+v located at %q to %+v located at %q", oldAgentVersion, oldAgentVersionedHome, newAgentVersion, newAgentVersionedHome)
	createUpdateMarker(t, topDir, newAgentVersion.version, newAgentVersion.hash, newAgentVersionedHome, oldAgentVersion.version, oldAgentVersion.hash, oldAgentVersionedHome)
}

func createFakeAgentInstall(t *testing.T, topDir, version, hash string, useVersionInPath bool) string {

	// create versioned home
	versionedHome := fmt.Sprintf("elastic-agent-%s", hash[:hashLen])
	if useVersionInPath {
		// use the version passed as parameter
		versionedHome = fmt.Sprintf("elastic-agent-%s-%s", version, hash[:hashLen])
	}

	absVersionedHomePath := filepath.Join(topDir, "data", versionedHome)
	err := os.MkdirAll(absVersionedHomePath, 0o750)
	require.NoError(t, err, "error creating fake install versioned home directory %q", absVersionedHomePath)

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
	err = os.WriteFile(filepath.Join(absVersionedHomePath, agentExecutableName), []byte(fmt.Sprintf("Placeholder for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing elastic agent binary placeholder %q", agentExecutableName)
	err = os.WriteFile(filepath.Join(absLogsDirPath, "fakelog.ndjson"), []byte(fmt.Sprintf("Sample logs for agent %s", version)), 0o750)
	require.NoErrorf(t, err, "error writing fake log placeholder %q")
	return versionedHome
}

func createLink(t *testing.T, topDir string, currentAgentVersionedHome string) {
	linkTarget := filepath.Join(currentAgentVersionedHome, agentName)
	linkName := agentName
	if runtime.GOOS == "windows" {
		linkTarget += ".exe"
		linkName += ".exe"
	}
	err := os.Symlink(filepath.Join("data", linkTarget), filepath.Join(topDir, linkName))
	require.NoError(t, err, "error creating test symlink to fake agent install")
}

func createUpdateMarker(t *testing.T, topDir string, newAgentVersion string, newAgentHash string, newAgentVersionedHome string, oldAgentVersion string, oldAgentHash string, oldAgentVersionedHome string) {
	updMarker := UpdateMarker{
		Version:           newAgentVersion,
		Hash:              newAgentHash,
		VersionedHome:     newAgentVersionedHome,
		UpdatedOn:         time.Now(),
		PrevVersion:       oldAgentVersion,
		PrevHash:          oldAgentHash,
		PrevVersionedHome: oldAgentVersionedHome,
		Acked:             true,
		Action:            nil,
		Details:           nil,
	}

	updMarkerSerializer := newMarkerSerializer(&updMarker)
	updMarkerBytes, err := yaml.Marshal(updMarkerSerializer)
	require.NoError(t, err, "error marshaling fake update marker")
	err = os.WriteFile(filepath.Join(topDir, "data", markerFilename), updMarkerBytes, 0o600)
	require.NoError(t, err, "error writing out fake update marker")
}
