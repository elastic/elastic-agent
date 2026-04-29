// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// TestReconcileMismatchedUpgrade exercises the reconcile path end-to-end against
// a temp top dir that mimics a real install: a "running" home, a "partial new"
// home referenced by the marker, and a symlink pointing at the wrong target.
// After reconcile, the symlink, active.commit, and marker should all describe
// the running install, and the partial new home should be gone.
func TestReconcileMismatchedUpgrade(t *testing.T) {
	const (
		myHash    = "aaaaaa"
		otherHash = "bbbbbb"
	)

	topDir := t.TempDir()
	dataDir := filepath.Join(topDir, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o755))

	// Running install ("we are this one").
	myHomeRel := filepath.Join("data", "elastic-agent-"+myHash)
	myHomeAbs := filepath.Join(topDir, myHomeRel)
	require.NoError(t, os.MkdirAll(myHomeAbs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(myHomeAbs, AgentName), []byte("fake-binary"), 0o755))

	// Partial "new" install referenced by the marker.
	otherHomeRel := filepath.Join("data", "elastic-agent-"+otherHash)
	otherHomeAbs := filepath.Join(topDir, otherHomeRel)
	require.NoError(t, os.MkdirAll(otherHomeAbs, 0o755))

	// Symlink currently points at the failed-target install.
	symlinkPath := filepath.Join(topDir, AgentName)
	require.NoError(t, os.Symlink(filepath.Join(otherHomeAbs, AgentName), symlinkPath))

	// Marker says current=other, prev=us, with a non-terminal state.
	marker := &UpdateMarker{
		Version:           "9.9.9",
		Hash:              otherHash,
		VersionedHome:     otherHomeRel,
		PrevVersion:       "9.0.0",
		PrevHash:          myHash,
		PrevVersionedHome: myHomeRel,
		Details:           details.NewDetails("9.9.9", details.StateReplacing, "test-action"),
	}
	require.NoError(t, SaveMarker(dataDir, marker, true))

	// Mock watcher takeover: hand back a real locker so the deferred Unlock
	// in reconcile is exercised.
	helper := NewMockWatcherHelper(t)
	locker := filelock.NewAppLocker(topDir, watcherApplockerFileName)
	helper.EXPECT().TakeOverWatcher(mock.Anything, mock.Anything, topDir).Return(locker, nil)

	log, _ := loggertest.New(t.Name())

	require.NoError(t, ReconcileMismatchedUpgrade(t.Context(), log, helper, topDir, myHomeRel, myHash, marker))

	// Symlink now points at our binary.
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(myHomeAbs, AgentName), target)

	// Partial "other" home is gone.
	_, err = os.Stat(otherHomeAbs)
	assert.ErrorIs(t, err, os.ErrNotExist)

	// active.commit reflects us.
	commitBytes, err := os.ReadFile(filepath.Join(topDir, agentCommitFile))
	require.NoError(t, err)
	assert.Equal(t, myHash, string(commitBytes))

	// Marker is rewritten as Failed and the action is preserved for ack.
	saved, err := LoadMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, saved.Details)
	assert.Equal(t, details.StateFailed, saved.Details.State)
	assert.Equal(t, otherHash, saved.Hash, "current hash unchanged so the action keeps describing the original target")
	assert.Equal(t, myHash, saved.PrevHash, "prev hash unchanged")
}

// TestReconcileMismatchedUpgrade_NoMarkerVersionedHome covers the marker.VersionedHome=""
// fallback so we don't try to RemoveAll(topDir).
func TestReconcileMismatchedUpgrade_NoMarkerVersionedHome(t *testing.T) {
	const myHash = "aaaaaa"

	topDir := t.TempDir()
	dataDir := filepath.Join(topDir, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o755))

	myHomeRel := filepath.Join("data", "elastic-agent-"+myHash)
	myHomeAbs := filepath.Join(topDir, myHomeRel)
	require.NoError(t, os.MkdirAll(myHomeAbs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(myHomeAbs, AgentName), []byte("fake-binary"), 0o755))

	require.NoError(t, os.Symlink(filepath.Join(myHomeAbs, AgentName), filepath.Join(topDir, AgentName)))

	marker := &UpdateMarker{
		Version:       "9.9.9",
		Hash:          "bbbbbb",
		VersionedHome: "", // legacy / partial marker with no path recorded
		PrevVersion:   "9.0.0",
		PrevHash:      myHash,
	}
	require.NoError(t, SaveMarker(dataDir, marker, true))

	helper := NewMockWatcherHelper(t)
	locker := filelock.NewAppLocker(topDir, watcherApplockerFileName)
	helper.EXPECT().TakeOverWatcher(mock.Anything, mock.Anything, topDir).Return(locker, nil)

	log, _ := loggertest.New(t.Name())

	require.NoError(t, ReconcileMismatchedUpgrade(t.Context(), log, helper, topDir, myHomeRel, myHash, marker))

	// Top dir still exists — no aggressive deletion when VersionedHome is empty.
	_, err := os.Stat(topDir)
	assert.NoError(t, err)

	saved, err := LoadMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, saved.Details)
	assert.Equal(t, details.StateFailed, saved.Details.State)
}

// TestCleanup_PreservesLiveInstallEvenWithStaleKeep is the regression test
// for the structural fix described in
// https://github.com/elastic/elastic-agent/issues/13505.
//
// Without the cleanup guard, when a watcher (or any other caller) builds the
// cleanup keep list from marker.VersionedHome and that path has already been
// removed from disk (for example by an aborted upgrade's rollbackInstall),
// cleanup "kept" the missing directory and deleted every other versioned
// home — including the one backing the live symlink, wiping the running
// install from disk while still in memory.
//
// The cleanup guard now resolves the live symlink and unconditionally adds
// its versioned home to the keep list, so a stale caller-supplied keep list
// can no longer cause data loss.
func TestCleanup_PreservesLiveInstallEvenWithStaleKeep(t *testing.T) {
	const (
		liveHash = "aaaaaa"
		// staleHash names a versioned home that was already removed from
		// disk — typical aftermath of rollbackInstall on a failed upgrade.
		staleHash = "bbbbbb"
	)

	topDir := t.TempDir()
	dataDir := filepath.Join(topDir, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o755))

	// The live install. This directory backs the running symlink; cleanup
	// must not delete it.
	liveHomeRel := filepath.Join("data", "elastic-agent-"+liveHash)
	liveHomeAbs := filepath.Join(topDir, liveHomeRel)
	require.NoError(t, os.MkdirAll(liveHomeAbs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(liveHomeAbs, AgentName), []byte("live-binary"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(liveHomeAbs, AgentName), filepath.Join(topDir, AgentName)))

	// A second versioned home that survived from some prior boot; not in
	// the keep list, so the guard should NOT preserve it. Only the live
	// symlink target is unconditionally protected.
	otherHomeRel := filepath.Join("data", "elastic-agent-cccccc")
	require.NoError(t, os.MkdirAll(filepath.Join(topDir, otherHomeRel), 0o755))

	// The caller-supplied keep list points at staleHash, which was never
	// created (or was already deleted). Without the guard, cleanup would
	// trust this and delete everything else.
	staleKeep := filepath.Join("data", "elastic-agent-"+staleHash)

	log, _ := loggertest.New(t.Name())
	require.NoError(t, cleanup(log, topDir, false, false, 0, staleKeep))

	// Guard kicked in: the live install survives even though it wasn't in
	// the caller's keep list.
	_, err := os.Stat(filepath.Join(liveHomeAbs, AgentName))
	require.NoError(t, err, "live install must survive cleanup with stale keep list (#13505 guard)")

	// Symlink still resolves.
	target, err := os.Readlink(filepath.Join(topDir, AgentName))
	require.NoError(t, err)
	_, err = os.Stat(target)
	assert.NoError(t, err, "symlink target must still exist")

	// The "kept" directory was missing to begin with and is still missing.
	_, err = os.Stat(filepath.Join(topDir, staleKeep))
	assert.ErrorIs(t, err, os.ErrNotExist)

	// The unrelated versioned home was correctly cleaned up — only the
	// live install gets the guard's protection.
	_, err = os.Stat(filepath.Join(topDir, otherHomeRel))
	assert.ErrorIs(t, err, os.ErrNotExist, "non-live, non-keep home should be cleaned")
}

// TestReconcileMismatchedUpgrade_TakeoverFailureProceeds confirms that a
// failing watcher takeover is best-effort: reconcile logs the failure and
// continues so the marker still ends up in a consistent terminal state.
func TestReconcileMismatchedUpgrade_TakeoverFailureProceeds(t *testing.T) {
	const (
		myHash    = "aaaaaa"
		otherHash = "bbbbbb"
	)

	topDir := t.TempDir()
	dataDir := filepath.Join(topDir, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0o755))

	myHomeRel := filepath.Join("data", "elastic-agent-"+myHash)
	myHomeAbs := filepath.Join(topDir, myHomeRel)
	require.NoError(t, os.MkdirAll(myHomeAbs, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(myHomeAbs, AgentName), []byte("fake-binary"), 0o755))

	require.NoError(t, os.Symlink(filepath.Join(myHomeAbs, AgentName), filepath.Join(topDir, AgentName)))

	marker := &UpdateMarker{
		Version:       "9.9.9",
		Hash:          otherHash,
		VersionedHome: filepath.Join("data", "elastic-agent-"+otherHash),
		PrevVersion:   "9.0.0",
		PrevHash:      myHash,
	}
	require.NoError(t, SaveMarker(dataDir, marker, true))

	helper := NewMockWatcherHelper(t)
	helper.EXPECT().TakeOverWatcher(mock.Anything, mock.Anything, topDir).Return(nil, assert.AnError)

	log, _ := loggertest.New(t.Name())

	require.NoError(t, ReconcileMismatchedUpgrade(t.Context(), log, helper, topDir, myHomeRel, myHash, marker))

	saved, err := LoadMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, saved.Details)
	assert.Equal(t, details.StateFailed, saved.Details.State)
}
