// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"context"
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
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

// setupRolledBackAgentDirs creates the state the restarted (rolled back) agent finds on disk after a
// watcher rollback: the previous home, the failed home with a log file and an upgrade marker in UPG_ROLLBACK.
// It returns the previous home, the failed home and the path of the failed home log file.
func setupRolledBackAgentDirs(t *testing.T, topDir string) (prev, failed, failedLog string) {
	t.Helper()
	prev = createFakeAgentInstall(t, topDir, "9.5.3", "0e70ce", true)
	failed = createFakeAgentInstall(t, topDir, "9.5.4", "b18dae", true)
	failedLog = filepath.Join(topDir, failed, "logs", "elastic-agent-watcher.ndjson")
	require.NoError(t, os.WriteFile(failedLog, []byte("Error detected, proceeding to rollback"), 0o644))

	require.NoError(t, SaveMarker(paths.DataFrom(topDir), &UpdateMarker{
		Version: "9.5.4", Hash: "b18dae", VersionedHome: failed,
		PrevVersion: "9.5.3", PrevHash: "0e70ce", PrevVersionedHome: prev,
		Details: &details.Details{State: details.StateRollback},
	}, false))
	return prev, failed, failedLog
}

// startupCleanup runs the CleanAvailableRollbacks part of what application.normalizeAgentInstalls runs when the agent starts.
func startupCleanup(t *testing.T, topDir, currentHome string) error {
	t.Helper()
	log, _ := loggertest.New(t.Name())
	marker, err := LoadMarker(paths.DataFrom(topDir))
	require.NoError(t, err)
	_, err = CleanAvailableRollbacks(log, ttl.NewTTLMarkerRegistry(log, topDir), topDir, currentHome, time.Now(),
		PreserveActiveUpgradeVersions(marker, CleanupExpiredRollbacks))
	return err
}

// failedUpgradeMarker is the upgrade marker of an upgrade from prev to failed.
func failedUpgradeMarker(prev, failed string) *UpdateMarker {
	return &UpdateMarker{Version: "9.5.4", Hash: "b18dae", VersionedHome: failed, PrevVersion: "9.5.3", PrevHash: "0e70ce", PrevVersionedHome: prev}
}

// The startup cleanup of the agent we rolled back to must keep the home of the failed upgrade and its logs
// when the failed home carries the retention marker.
func TestRetainFailedUpgradeLogs_SurvivesStartupCleanup(t *testing.T) {
	log, _ := loggertest.New(t.Name())

	t.Run("without retention marker the failed home is removed", func(t *testing.T) {
		topDir := t.TempDir()
		prev, failed, failedLog := setupRolledBackAgentDirs(t, topDir)
		require.NoError(t, startupCleanup(t, topDir, prev))
		assert.NoFileExists(t, failedLog)
		assert.NoDirExists(t, filepath.Join(topDir, failed))
	})

	t.Run("with retention marker the failed home survives", func(t *testing.T) {
		topDir := t.TempDir()
		prev, failed, failedLog := setupRolledBackAgentDirs(t, topDir)
		require.NoError(t, retainFailedUpgradeLogs(log, topDir, failed, failedUpgradeMarker(prev, failed), time.Hour))

		require.NoError(t, startupCleanup(t, topDir, prev))
		assert.FileExists(t, failedLog, "logs of the failed upgrade must survive the startup cleanup")
	})

	t.Run("expired retention marker: the failed home is removed whole", func(t *testing.T) {
		topDir := t.TempDir()
		prev, failed, failedLog := setupRolledBackAgentDirs(t, topDir)
		require.NoError(t, retainFailedUpgradeLogs(log, topDir, failed, failedUpgradeMarker(prev, failed), -time.Hour))

		require.NoError(t, startupCleanup(t, topDir, prev))
		assert.NoFileExists(t, failedLog)
		assert.NoDirExists(t, filepath.Join(topDir, failed))
	})
}

func TestRetainFailedUpgradeLogs_KeepsExistingMarkers(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()
	prev, failed, _ := setupRolledBackAgentDirs(t, topDir)
	registry := ttl.NewTTLMarkerRegistry(log, topDir)
	prevTTL := ttl.TTLMarker{Version: "9.5.3", Hash: "0e70ce", ValidUntil: time.Now().Add(24 * time.Hour)}
	require.NoError(t, registry.Set(map[string]ttl.TTLMarker{prev: prevTTL}))

	validUntil := time.Now().Add(time.Hour)
	require.NoError(t, retainFailedUpgradeLogs(log, topDir, failed, failedUpgradeMarker(prev, failed), time.Hour))

	got, malformed, err := registry.GetAll()
	require.NoError(t, err)
	assert.Empty(t, malformed)
	require.Len(t, got, 2)
	assert.Equal(t, prevTTL.ValidUntil.Unix(), got[prev].ValidUntil.Unix(), "the existing marker must be left untouched")
	assert.True(t, got[prev].IsRollbackTarget())
	assert.Equal(t, ttl.KindDiagnostics, got[failed].Kind)
	assert.WithinDuration(t, validUntil, got[failed].ValidUntil, time.Second)
}

func TestRetainFailedUpgradeLogs_WriteFailure(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	// the failed home does not exist, so the marker cannot be written
	home := "data/elastic-agent-9.5.4-b18dae"
	err := retainFailedUpgradeLogs(log, t.TempDir(), home, &UpdateMarker{Version: "9.5.4", Hash: "b18dae", VersionedHome: home}, time.Hour)
	assert.Error(t, err)
}

func TestRetainedHome(t *testing.T) {
	failedHome := filepath.Join("data", "elastic-agent-9.5.4-b18dae")
	prevHome := filepath.Join("data", "elastic-agent-9.5.3-0e70ce")

	assert.Equal(t, "", retainedHome(nil))
	assert.Equal(t, failedHome, retainedHome(&UpdateMarker{Hash: "b18dae2c72", VersionedHome: failedHome, PrevVersionedHome: prevHome}))
	assert.Equal(t, filepath.Join("data", "elastic-agent-b18dae"),
		retainedHome(&UpdateMarker{Hash: "b18dae2c72", PrevVersionedHome: prevHome}), "marker of older agents has no versioned home")
	assert.Equal(t, "", retainedHome(&UpdateMarker{Hash: "b1", PrevVersionedHome: prevHome}), "no failed home in the marker")
	assert.Equal(t, "", retainedHome(&UpdateMarker{VersionedHome: prevHome, PrevVersionedHome: prevHome}), "the home we roll back to is never retained")

	// the retained home gets stripped, so it must be a data/elastic-agent-* directory
	for _, invalid := range []string{".", "data", "..", filepath.Join("data", "..", "etc"), filepath.Join("data", "other"), filepath.Join("data", "elastic-agent-1", "nested"), string(filepath.Separator)} {
		assert.Equal(t, "", retainedHome(&UpdateMarker{VersionedHome: invalid, PrevVersionedHome: prevHome}), "%q is not a versioned home", invalid)
	}
}

func TestRollbackWithOpts_RetainsLogsOfFailedUpgrade(t *testing.T) {
	var logs *observer.ObservedLogs
	setup := func(t *testing.T, onRestart func()) (log *logger.Logger, topDir string, mockClient *client.MockClient) {
		t.Helper()
		log, logs = loggertest.New(t.Name())
		topDir = t.TempDir()
		setupAgents(t, log, topDir, setupAgentInstallations{
			installedAgents: []testAgentInstall{
				{version: version123Snapshot, useVersionInPath: true},
				{version: version456Snapshot, useVersionInPath: true},
			},
			upgradeFrom:  version123Snapshot,
			upgradeTo:    version456Snapshot,
			currentAgent: version456Snapshot,
		}, true)
		mockClient = client.NewMockClient(t)
		mockClient.EXPECT().Connect(mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mockClient.EXPECT().Disconnect().Return()
		mockClient.EXPECT().Restart(mock.Anything).Run(func(_ context.Context) {
			if onRestart != nil {
				onRestart()
			}
		}).Return(nil).Once()
		return log, topDir, mockClient
	}
	prevHome := "data/elastic-agent-1.2.3-SNAPSHOT-abcdef"
	failedHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
	failedMarker := &UpdateMarker{Version: "4.5.6-SNAPSHOT", Hash: "ghijkl", VersionedHome: failedHome, PrevVersionedHome: prevHome}
	withLogsRetention := func(marker *UpdateMarker) RollbackOpt {
		return func(rs *RollbackSettings) { rs.SetLogsRetention(marker, time.Hour) }
	}

	t.Run("the failed home is marked before the restart and stripped to its logs after it", func(t *testing.T) {
		var topDir string
		onRestart := func() {
			assert.FileExists(t, filepath.Join(topDir, failedHome, ttl.MarkerFileName), "the home must be marked before the restart")
			assert.DirExists(t, filepath.Join(topDir, failedHome, "components"), "the home must not be stripped before the restart")
		}
		var log *logger.Logger
		var mockClient *client.MockClient
		log, topDir, mockClient = setup(t, onRestart)
		failedLog := filepath.Join(topDir, failedHome, "logs", "elastic-agent-watcher.ndjson")
		require.NoError(t, os.WriteFile(failedLog, []byte("Error detected, proceeding to rollback"), 0o640))

		require.NoError(t, RollbackWithOpts(t.Context(), log, mockClient, topDir, prevHome, "abcdef", withLogsRetention(failedMarker)))

		assert.FileExists(t, failedLog, "the logs of the failed upgrade must survive the strip")
		assert.FileExists(t, filepath.Join(topDir, failedHome, ttl.MarkerFileName))
		assert.True(t, hasOnlyLogs(log, filepath.Join(topDir, failedHome)), "the failed home must be stripped down to its logs")
		assertAgentInstallExists(t, filepath.Join(topDir, prevHome), paths.BinaryName)
	})

	t.Run("the failed home is stripped even if the agent we rolled back to rewrote its marker without the kind", func(t *testing.T) {
		var topDir string
		onRestart := func() {
			// what an agent that does not know kinds does when it starts: it rewrites the markers it reads
			legacyMarker := "version: 4.5.6-SNAPSHOT\nhash: ghijkl\nvalid_until: " + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + "\n"
			require.NoError(t, os.WriteFile(filepath.Join(topDir, failedHome, ttl.MarkerFileName), []byte(legacyMarker), 0o660))
		}
		var log *logger.Logger
		var mockClient *client.MockClient
		log, topDir, mockClient = setup(t, onRestart)
		failedLog := filepath.Join(topDir, failedHome, "logs", "elastic-agent-watcher.ndjson")
		require.NoError(t, os.WriteFile(failedLog, []byte("Error detected, proceeding to rollback"), 0o640))

		require.NoError(t, RollbackWithOpts(t.Context(), log, mockClient, topDir, prevHome, "abcdef", withLogsRetention(failedMarker)))

		assert.True(t, hasOnlyLogs(log, filepath.Join(topDir, failedHome)), "the failed home must be stripped down to its logs")
		assert.FileExists(t, failedLog, "the logs must survive the strip")
		assert.FileExists(t, filepath.Join(topDir, failedHome, ttl.MarkerFileName))
	})

	t.Run("the home rolled back to is never marked nor stripped", func(t *testing.T) {
		log, topDir, mockClient := setup(t, nil)

		marker := &UpdateMarker{Version: "1.2.3-SNAPSHOT", Hash: "abcdef", VersionedHome: prevHome, PrevVersionedHome: prevHome}
		require.NoError(t, RollbackWithOpts(t.Context(), log, mockClient, topDir, prevHome, "abcdef", withLogsRetention(marker)))

		assertAgentInstallExists(t, filepath.Join(topDir, prevHome), paths.BinaryName)
		assert.NoFileExists(t, filepath.Join(topDir, prevHome, ttl.MarkerFileName))
	})

	t.Run("a failure to retain the logs does not block the rollback", func(t *testing.T) {
		log, topDir, mockClient := setup(t, nil)

		// the failed home does not exist so it cannot be marked
		marker := &UpdateMarker{Version: "9.9.9", Hash: "nonexistent", VersionedHome: "data/elastic-agent-9.9.9-nonexi", PrevVersionedHome: prevHome}
		require.NoError(t, RollbackWithOpts(t.Context(), log, mockClient, topDir, prevHome, "abcdef", withLogsRetention(marker)))

		assert.NotEmpty(t, logs.FilterMessageSnippet("failed to retain the logs").All(), "the failure must be logged")
		assertAgentInstallExists(t, filepath.Join(topDir, prevHome), paths.BinaryName)
	})
}

// The home we roll back to can be derived from the previous hash when the marker does not record it:
// it must not be mistaken for the failed home.
func TestRollbackWithOpts_NeverStripsThePreviousHomeDerivedFromItsHash(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()
	setupAgents(t, log, topDir, setupAgentInstallations{
		installedAgents: []testAgentInstall{
			{version: version123Snapshot, useVersionInPath: false},
			{version: version456Snapshot, useVersionInPath: true},
		},
		upgradeFrom:  version123Snapshot,
		upgradeTo:    version456Snapshot,
		currentAgent: version456Snapshot,
	}, true)
	mockClient := client.NewMockClient(t)
	mockClient.EXPECT().Connect(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockClient.EXPECT().Disconnect().Return()
	mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

	prevHome := filepath.Join("data", "elastic-agent-abcdef")
	marker := &UpdateMarker{Version: "1.2.3-SNAPSHOT", Hash: "abcdef", VersionedHome: prevHome}
	retention := func(rs *RollbackSettings) { rs.SetLogsRetention(marker, time.Hour) }

	require.NoError(t, RollbackWithOpts(t.Context(), log, mockClient, topDir, "", "abcdef", retention))

	assertAgentInstallExists(t, filepath.Join(topDir, prevHome), paths.BinaryName)
	assert.NoFileExists(t, filepath.Join(topDir, prevHome, ttl.MarkerFileName))
}

// A supervisor can start the agent we roll back to as soon as the symlink changes, and that agent's startup
// cleanup removes homes without a TTL marker: the failed home must be marked before the symlink changes.
// A symlink change that fails makes the rollback stop right there, so a marker that exists then was written before it.
func TestRollbackWithOpts_MarksTheFailedHomeBeforeChangingTheSymlink(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()
	setupAgents(t, log, topDir, setupAgentInstallations{
		installedAgents: []testAgentInstall{
			{version: version123Snapshot, useVersionInPath: true},
			{version: version456Snapshot, useVersionInPath: true},
		},
		upgradeFrom:  version123Snapshot,
		upgradeTo:    version456Snapshot,
		currentAgent: version456Snapshot,
	}, true)
	prevHome := "data/elastic-agent-1.2.3-SNAPSHOT-abcdef"
	failedHome := filepath.Join("data", "elastic-agent-4.5.6-SNAPSHOT-ghijkl")
	// the symlink cannot point to an install without a binary
	require.NoError(t, os.Remove(paths.BinaryPath(filepath.Join(topDir, prevHome), paths.BinaryName)))
	marker := &UpdateMarker{Version: "4.5.6-SNAPSHOT", Hash: "ghijkl", VersionedHome: failedHome, PrevVersionedHome: prevHome}

	// the agent must not be restarted, the mock fails the test if it is contacted
	err := RollbackWithOpts(t.Context(), log, client.NewMockClient(t), topDir, prevHome, "abcdef", func(rs *RollbackSettings) {
		rs.SetLogsRetention(marker, time.Hour)
	})

	require.Error(t, err, "the rollback must stop at the symlink change")
	assert.FileExists(t, filepath.Join(topDir, failedHome, ttl.MarkerFileName), "the failed home must be marked before the symlink changes")
}

// The agent has been rolled back and restarted when the cleanup runs: its failure must not fail the rollback.
func TestRollbackWithOpts_CleanupFailureDoesNotFailTheRollback(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs something that cannot be removed, which permissions do not give on Windows or as root")
	}
	log, logs := loggertest.New(t.Name())
	topDir := t.TempDir()
	setupAgents(t, log, topDir, setupAgentInstallations{
		installedAgents: []testAgentInstall{
			{version: version123Snapshot, useVersionInPath: true},
			{version: version456Snapshot, useVersionInPath: true},
		},
		upgradeFrom:  version123Snapshot,
		upgradeTo:    version456Snapshot,
		currentAgent: version456Snapshot,
	}, true)
	// an orphan that the cleanup cannot remove
	orphan := createFakeAgentInstall(t, topDir, "0.0.1", "aaaaaa", true)
	locked := filepath.Join(topDir, orphan, "components", "locked")
	require.NoError(t, os.MkdirAll(locked, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(locked, "file"), []byte("x"), 0o640))
	require.NoError(t, os.Chmod(locked, 0o500))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })
	mockClient := client.NewMockClient(t)
	mockClient.EXPECT().Connect(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockClient.EXPECT().Disconnect().Return()
	mockClient.EXPECT().Restart(mock.Anything).Return(nil).Once()

	err := RollbackWithOpts(t.Context(), log, mockClient, topDir, "data/elastic-agent-1.2.3-SNAPSHOT-abcdef", "abcdef")

	require.NoError(t, err)
	assert.NotEmpty(t, logs.FilterMessageSnippet("cleanup after rollback failed").All(), "the cleanup failure must be logged")
}
