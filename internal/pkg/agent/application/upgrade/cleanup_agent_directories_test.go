// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// shouldRemove unit tests. These build a dirClassifier literal directly — no
// filesystem fixture is needed — so each of the 9 decision-matrix rows can
// be exercised in isolation.

func newTestDirClassifier(t *testing.T) *dirClassifier {
	t.Helper()
	log, _ := loggertest.New(t.Name())
	return &dirClassifier{
		log: log,
	}
}

func TestCleanupAgentDirectories_Row1_CallerProtected(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.callerProtected = map[string]bool{"data/elastic-agent-keep": true}
	// Even an expired TTL must not flip this — caller-protected wins.
	dc.expiredTTL = map[string]bool{"data/elastic-agent-keep": true}
	assert.False(t, dc.shouldRemove("data/elastic-agent-keep"))
}

func TestCleanupAgentDirectories_Row2_UnexpiredTTL(t *testing.T) {
	dc := newTestDirClassifier(t)
	// Has TTL, filter said NOT removable (unexpired) -> keep.
	dc.expiredTTL = map[string]bool{"data/elastic-agent-keep": false}
	assert.False(t, dc.shouldRemove("data/elastic-agent-keep"))
}

func TestCleanupAgentDirectories_Row3_ExpiredTTLOnSymlinkTarget(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = "data/elastic-agent-live"
	dc.expiredTTL = map[string]bool{"data/elastic-agent-live": true}
	// Expired TTL, but the dir is the live symlink target -> keep.
	assert.False(t, dc.shouldRemove("data/elastic-agent-live"))
}

func TestCleanupAgentDirectories_Row4_ExpiredTTL_SymlinkUnresolvable(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkErr = errors.New("boom")
	dc.expiredTTL = map[string]bool{"data/elastic-agent-expired": true}
	// Expired TTL with no symlink to defend it -> remove (row 4).
	// This is the Windows regression case: an unreadable symlink must not
	// block the sweep of clearly-expired entries.
	assert.True(t, dc.shouldRemove("data/elastic-agent-expired"))
}

func TestCleanupAgentDirectories_Row5_Orphan_SymlinkUnresolvable(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkErr = errors.New("boom")
	// Orphan dir, symlink unreadable -> keep conservatively.
	assert.False(t, dc.shouldRemove("data/elastic-agent-orphan"))
}

func TestCleanupAgentDirectories_Row6_Orphan_IsSymlinkTarget(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = "data/elastic-agent-live"
	// Orphan dir but it IS the live install -> keep.
	assert.False(t, dc.shouldRemove("data/elastic-agent-live"))
}

func TestCleanupAgentDirectories_Row7_Orphan_MarkerUnreadable(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = "data/elastic-agent-live"
	dc.markerErr = errors.New("marker unreadable")
	// Orphan dir, marker unreadable -> keep (cannot verify marker doesn't
	// reference it).
	assert.False(t, dc.shouldRemove("data/elastic-agent-orphan"))
}

func TestCleanupAgentDirectories_Row8_Orphan_MarkerReferencesIt(t *testing.T) {
	tests := []struct {
		name                 string
		requireMarkerDetails bool
		detailsPresent       bool
		state                details.State
		wantRemove           bool
	}{
		{
			name:                 "active marker, details non-nil, lenient mode -> keep",
			requireMarkerDetails: false,
			detailsPresent:       true,
			state:                details.StateWatching,
			wantRemove:           false,
		},
		{
			name:                 "active marker, details nil, lenient mode -> keep",
			requireMarkerDetails: false,
			detailsPresent:       false,
			wantRemove:           false,
		},
		{
			name:                 "active marker, details non-nil, strict mode -> keep",
			requireMarkerDetails: true,
			detailsPresent:       true,
			state:                details.StateWatching,
			wantRemove:           false,
		},
		{
			name:                 "active marker, details nil, strict mode -> remove (no proof of active upgrade)",
			requireMarkerDetails: true,
			detailsPresent:       false,
			wantRemove:           true,
		},
		{
			name:                 "terminal marker (UPG_COMPLETE) -> remove",
			requireMarkerDetails: false,
			detailsPresent:       true,
			state:                details.StateCompleted,
			wantRemove:           true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dc := newTestDirClassifier(t)
			dc.symlinkTarget = "data/elastic-agent-live"
			dc.requireMarkerDetails = tc.requireMarkerDetails
			marker := &UpdateMarker{
				VersionedHome:     "data/elastic-agent-target",
				PrevVersionedHome: "data/elastic-agent-prev",
			}
			if tc.detailsPresent {
				marker.Details = &details.Details{State: tc.state}
			}
			dc.marker = marker

			assert.Equal(t, tc.wantRemove, dc.shouldRemove("data/elastic-agent-target"))
		})
	}
}

func TestCleanupAgentDirectories_Row9_Orphan_AllVerificationPasses(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = "data/elastic-agent-live"
	dc.marker = &UpdateMarker{
		Details:           &details.Details{State: details.StateCompleted},
		VersionedHome:     "data/elastic-agent-live",
		PrevVersionedHome: "data/elastic-agent-prev",
	}
	// Orphan dir, symlink resolved, marker terminal -> safe to remove.
	assert.True(t, dc.shouldRemove("data/elastic-agent-orphan"))
}

// cleanupAgentDirectories end-to-end tests using real filesystem fixtures.

func TestCleanupAgentDirectories_ReturnsDegradedSentinel_OnSymlinkErr(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	// One install, no symlink. liveVersionedHome will fail.
	relHome := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)

	// Unexpired TTL on the install so the scheduler can still compute the
	// next wake-up from leftoverRollbacks even when cleanup is degraded.
	validUntil := time.Now().Add(24 * time.Hour)
	wantMarker := ttl.TTLMarker{Version: "1.0.0", Hash: "aaaaaa", ValidUntil: validUntil}
	source := ttl.NewTTLMarkerRegistry(log, topDir)
	require.NoError(t,
		source.Set(map[string]ttl.TTLMarker{relHome: wantMarker}),
		"writing unexpired TTL marker for fixture")

	leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, true, false)
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	// Degraded must still return populated leftoverRollbacks so the scheduler
	// can compute the next wake-up time (see manual_rollback.go scheduler).
	require.NotNil(t, leftover)
	got, ok := leftover[relHome]
	require.True(t, ok, "unexpired TTL entry must be in leftoverRollbacks")
	assert.Equal(t, wantMarker.Version, got.Version)
	assert.Equal(t, wantMarker.Hash, got.Hash)
	// YAML round-trip strips monotonic clock; tolerate sub-second drift.
	assert.WithinDuration(t, wantMarker.ValidUntil, got.ValidUntil, time.Second)
}

func TestCleanupAgentDirectories_ReturnsDegradedSentinel_OnMarkerErr(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	live := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)
	createLink(t, topDir, live)

	// Second install with an unexpired TTL: this is the entry whose presence
	// in leftoverRollbacks the scheduler depends on for the next wake-up.
	rollbackHome := createFakeAgentInstall(t, topDir, "0.9.0", "bbbbbb", true)
	validUntil := time.Now().Add(24 * time.Hour)
	wantMarker := ttl.TTLMarker{Version: "0.9.0", Hash: "bbbbbb", ValidUntil: validUntil}
	source := ttl.NewTTLMarkerRegistry(log, topDir)
	require.NoError(t,
		source.Set(map[string]ttl.TTLMarker{rollbackHome: wantMarker}),
		"writing unexpired TTL marker for fixture")

	// Write a malformed upgrade marker so LoadMarker returns an error.
	require.NoError(t, os.MkdirAll(filepath.Join(topDir, "data"), 0o750))
	require.NoError(t,
		os.WriteFile(filepath.Join(topDir, "data", markerFilename), []byte("not: valid: yaml: ["), 0o600),
		"writing malformed upgrade marker")

	leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, true, false)
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	require.NotNil(t, leftover)
	got, ok := leftover[rollbackHome]
	require.True(t, ok, "unexpired TTL entry must be in leftoverRollbacks")
	assert.Equal(t, wantMarker.Version, got.Version)
	assert.Equal(t, wantMarker.Hash, got.Hash)
	assert.WithinDuration(t, wantMarker.ValidUntil, got.ValidUntil, time.Second)
}

// Wrapper-level tests: confirm Cleanup preserves the upgrade marker when
// verification was degraded.

func TestCleanup_PreservesMarker_WhenSymlinkUnresolvable(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	require.NoError(t, os.MkdirAll(filepath.Join(topDir, "data"), 0o750))
	markerPath := filepath.Join(topDir, "data", markerFilename)
	require.NoError(t,
		SaveMarker(filepath.Join(topDir, "data"), &UpdateMarker{Version: "1.2.3", Hash: "abc"}, true))

	// No symlink. liveVersionedHome will fail.

	err := cleanup(log, topDir, true, false, 0)
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	assert.FileExists(t, markerPath,
		"upgrade marker must survive a degraded cleanup so the next run can verify with full info")
}

func TestCleanup_PreservesMarker_WhenMarkerUnreadable(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	live := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)
	createLink(t, topDir, live)

	markerPath := filepath.Join(topDir, "data", markerFilename)
	require.NoError(t, os.MkdirAll(filepath.Join(topDir, "data"), 0o750))
	require.NoError(t,
		os.WriteFile(markerPath, []byte("not: valid: yaml: ["), 0o600),
		"writing malformed upgrade marker")

	err := cleanup(log, topDir, true, false, 0)
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	assert.FileExists(t, markerPath,
		"unreadable upgrade marker must NOT be deleted; the next run may be able to read it")

	// Live install must survive too — orphan kept conservatively when marker
	// is unreadable.
	agentExecutableName := AgentName
	if runtime.GOOS == "windows" {
		agentExecutableName += ".exe"
	}
	assertAgentInstallExists(t, filepath.Join(topDir, live), agentExecutableName)
}
