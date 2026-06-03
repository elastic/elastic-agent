// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/ttl"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

func TestIsDegradedOnly(t *testing.T) {
	fsErr := errors.New("disk error")
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain non-degraded error", err: fsErr, want: false},
		{name: "plain errCleanupDegraded", err: errCleanupDegraded, want: true},
		{name: "join of errCleanupDegraded alone", err: errors.Join(errCleanupDegraded), want: true},
		{name: "join of fsErr and errCleanupDegraded", err: errors.Join(fsErr, errCleanupDegraded), want: false},
		{name: "join of errCleanupDegraded and fsErr", err: errors.Join(errCleanupDegraded, fsErr), want: false},
		// fmt.Errorf wraps errCleanupDegraded with no non-degraded siblings → true.
		{name: "fmt.Errorf wrap of errCleanupDegraded has no non-degraded siblings", err: fmt.Errorf("ctx: %w", errCleanupDegraded), want: true},
		// fmt.Errorf wraps a join that has a non-degraded sibling → false (recursion catches it).
		{name: "fmt.Errorf wrap of mixed join is not degraded-only", err: fmt.Errorf("ctx: %w", errors.Join(fsErr, errCleanupDegraded)), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isDegradedOnly(tc.err))
		})
	}
}

func newTestDirClassifier(t *testing.T) *dirClassifier {
	t.Helper()
	log, _ := loggertest.New(t.Name())
	return &dirClassifier{
		log: log,
	}
}

func TestCleanupAgentDirectories_CallerProtected(t *testing.T) {
	dir := filepath.Join("data", "elastic-agent-keep")
	dc := newTestDirClassifier(t)
	dc.callerProtected = map[string]bool{dir: true}
	// Even an expired TTL must not flip this — caller-protected wins.
	dc.expiredTTL = map[string]bool{dir: true}
	assert.False(t, dc.shouldRemove(dir))
}

func TestCleanupAgentDirectories_UnexpiredTTL(t *testing.T) {
	dir := filepath.Join("data", "elastic-agent-keep")
	dc := newTestDirClassifier(t)
	// Has TTL, filter said NOT removable (unexpired) -> keep.
	dc.expiredTTL = map[string]bool{dir: false}
	assert.False(t, dc.shouldRemove(dir))
}

func TestCleanupAgentDirectories_ExpiredTTLOnSymlinkTarget(t *testing.T) {
	live := filepath.Join("data", "elastic-agent-live")
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = live
	dc.expiredTTL = map[string]bool{live: true}
	// Expired TTL, but the dir is the live symlink target -> keep.
	assert.False(t, dc.shouldRemove(live))
}

func TestCleanupAgentDirectories_ExpiredTTL_SymlinkUnresolvable(t *testing.T) {
	expired := filepath.Join("data", "elastic-agent-expired")
	dc := newTestDirClassifier(t)
	dc.symlinkErr = errors.New("boom")
	dc.expiredTTL = map[string]bool{expired: true}
	// Windows regression: an unreadable symlink must not block the sweep of expired entries.
	assert.True(t, dc.shouldRemove(expired))
}

func TestCleanupAgentDirectories_Orphan_SymlinkUnresolvable(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkErr = errors.New("boom")
	// Orphan dir, symlink unreadable -> keep conservatively.
	assert.False(t, dc.shouldRemove(filepath.Join("data", "elastic-agent-orphan")))
}

func TestCleanupAgentDirectories_Orphan_IsSymlinkTarget(t *testing.T) {
	live := filepath.Join("data", "elastic-agent-live")
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = live
	// Orphan dir but it IS the live install -> keep.
	assert.False(t, dc.shouldRemove(live))
}

func TestCleanupAgentDirectories_Orphan_MarkerUnreadable(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = filepath.Join("data", "elastic-agent-live")
	dc.markerErr = errors.New("marker unreadable")
	// Orphan dir, marker unreadable -> keep (cannot verify marker doesn't
	// reference it).
	assert.False(t, dc.shouldRemove(filepath.Join("data", "elastic-agent-orphan")))
}

func TestCleanupAgentDirectories_Orphan_MarkerReferencesIt(t *testing.T) {
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
	targetHome := filepath.Join("data", "elastic-agent-target")
	prevHome := filepath.Join("data", "elastic-agent-prev")
	liveHome := filepath.Join("data", "elastic-agent-live")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dc := newTestDirClassifier(t)
			dc.symlinkTarget = liveHome
			dc.requireMarkerDetails = tc.requireMarkerDetails
			marker := &UpdateMarker{
				VersionedHome:     targetHome,
				PrevVersionedHome: prevHome,
			}
			if tc.detailsPresent {
				marker.Details = &details.Details{State: tc.state}
			}
			dc.marker = marker

			t.Run("VersionedHome", func(t *testing.T) {
				assert.Equal(t, tc.wantRemove, dc.shouldRemove(targetHome))
			})
			t.Run("PrevVersionedHome", func(t *testing.T) {
				assert.Equal(t, tc.wantRemove, dc.shouldRemove(prevHome))
			})
		})
	}
}

func TestCleanupAgentDirectories_Orphan_TerminalMarker_AllowsRemoval(t *testing.T) {
	dc := newTestDirClassifier(t)
	dc.symlinkTarget = filepath.Join("data", "elastic-agent-live")
	dc.marker = &UpdateMarker{
		Details:           &details.Details{State: details.StateCompleted},
		VersionedHome:     filepath.Join("data", "elastic-agent-live"),
		PrevVersionedHome: filepath.Join("data", "elastic-agent-prev"),
	}
	// Orphan dir, symlink resolved, marker terminal -> safe to remove.
	assert.True(t, dc.shouldRemove(filepath.Join("data", "elastic-agent-orphan")))
}

func TestCleanupAgentDirectories_ReturnsDegradedSentinel_OnSymlinkErr(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	// One install, no symlink.
	relHome := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)

	// Unexpired TTL on the install — must be returned in leftoverRollbacks even when cleanup is degraded.
	validUntil := time.Now().Add(24 * time.Hour)
	wantMarker := ttl.TTLMarker{Version: "1.0.0", Hash: "aaaaaa", ValidUntil: validUntil}
	source := ttl.NewTTLMarkerRegistry(log, topDir)
	require.NoError(t,
		source.Set(map[string]ttl.TTLMarker{relHome: wantMarker}),
		"writing unexpired TTL marker for fixture")

	leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, cleanupOpts{requireMarkerDetails: true})
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	// Degraded state must not drop unexpired rollbacks — the caller uses them to schedule the next cleanup.
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

	// Second install with an unexpired TTL.
	rollbackHome := createFakeAgentInstall(t, topDir, "0.9.0", "bbbbbb", true)
	validUntil := time.Now().Add(24 * time.Hour)
	wantMarker := ttl.TTLMarker{Version: "0.9.0", Hash: "bbbbbb", ValidUntil: validUntil}
	source := ttl.NewTTLMarkerRegistry(log, topDir)
	require.NoError(t,
		source.Set(map[string]ttl.TTLMarker{rollbackHome: wantMarker}),
		"writing unexpired TTL marker for fixture")

	// Write a malformed upgrade marker.
	require.NoError(t, os.MkdirAll(filepath.Join(topDir, "data"), 0o750))
	require.NoError(t,
		os.WriteFile(filepath.Join(topDir, "data", markerFilename), []byte("not: valid: yaml: ["), 0o600),
		"writing malformed upgrade marker")

	leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, cleanupOpts{requireMarkerDetails: true})
	require.Error(t, err)
	require.ErrorIs(t, err, errCleanupDegraded)

	require.NotNil(t, leftover)
	got, ok := leftover[rollbackHome]
	require.True(t, ok, "unexpired TTL entry must be in leftoverRollbacks")
	assert.Equal(t, wantMarker.Version, got.Version)
	assert.Equal(t, wantMarker.Hash, got.Hash)
	assert.WithinDuration(t, wantMarker.ValidUntil, got.ValidUntil, time.Second)
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

func TestCleanupAgentDirectories_ReconcilesTTLRegistry(t *testing.T) {
	log, _ := loggertest.New(t.Name())
	topDir := t.TempDir()

	// Live install with an unexpired TTL.
	live := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)
	createLink(t, topDir, live)
	validUntil := time.Now().Add(24 * time.Hour)
	unexpiredMarker := ttl.TTLMarker{Version: "1.0.0", Hash: "aaaaaa", ValidUntil: validUntil}

	// Expired install (no symlink, will be swept).
	expired := createFakeAgentInstall(t, topDir, "0.9.0", "bbbbbb", true)
	expiredMarker := ttl.TTLMarker{Version: "0.9.0", Hash: "bbbbbb", ValidUntil: time.Now().Add(-1 * time.Hour)}

	source := ttl.NewTTLMarkerRegistry(log, topDir)
	require.NoError(t, source.Set(map[string]ttl.TTLMarker{
		live:    unexpiredMarker,
		expired: expiredMarker,
	}))

	leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, cleanupOpts{requireMarkerDetails: true})
	require.NoError(t, err)

	// Expired directory should be removed.
	assert.NoDirExists(t, filepath.Join(topDir, expired))

	// Only the unexpired rollback survives.
	require.Contains(t, leftover, live)
	assert.NotContains(t, leftover, expired)

	// TTL registry on disk must be reconciled: only the unexpired entry remains.
	onDisk, _, err := source.GetAll()
	require.NoError(t, err)
	assert.Contains(t, onDisk, live, "unexpired TTL must remain in registry")
	assert.NotContains(t, onDisk, expired, "expired TTL must be removed from registry")
}

func TestCleanupAgentDirectories_SetCondition(t *testing.T) {
	t.Run("malformed entry triggers Remove", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		// Live install with symlink ensures non-degraded state.
		live := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)
		createLink(t, topDir, live)

		source := ttl.NewMockSource(t)
		// GetAll returns no parsed markers but one malformed entry.
		source.EXPECT().GetAll().Return(
			map[string]ttl.TTLMarker{},
			map[string]error{live: errors.New("parse error")},
			nil,
		)
		// Remove must be called for the malformed entry only.
		source.EXPECT().Remove(live).Return(nil)

		_, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, cleanupOpts{})
		require.NoError(t, err)
	})

	t.Run("no malformed entries skips Remove", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		topDir := t.TempDir()

		// Live install with symlink ensures non-degraded state.
		live := createFakeAgentInstall(t, topDir, "1.0.0", "aaaaaa", true)
		createLink(t, topDir, live)

		unexpired := ttl.TTLMarker{Version: "1.0.0", Hash: "aaaaaa", ValidUntil: time.Now().Add(24 * time.Hour)}
		source := ttl.NewMockSource(t)
		// GetAll returns one unexpired marker and no malformed entries.
		source.EXPECT().GetAll().Return(
			map[string]ttl.TTLMarker{live: unexpired},
			map[string]error{},
			nil,
		)
		// No Remove or Set calls expected — mock will fail the test if either is called.

		leftover, err := cleanupAgentDirectories(log, topDir, time.Now(), source, CleanupExpiredRollbacks, nil, cleanupOpts{})
		require.NoError(t, err)
		assert.Contains(t, leftover, live)
	})
}

func TestHasOnlyLogs(t *testing.T) {
	tests := []struct {
		name  string
		setup func(dir string)
		want  bool
	}{
		{
			name:  "empty dir",
			setup: func(dir string) {},
			want:  false,
		},
		{
			name: "only logs dir",
			setup: func(dir string) {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "logs"), 0o755))
			},
			want: true,
		},
		{
			name: "logs dir plus extra file",
			setup: func(dir string) {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "logs"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o644))
			},
			want: false,
		},
		{
			name: "logs dir plus hidden file",
			setup: func(dir string) {
				require.NoError(t, os.Mkdir(filepath.Join(dir, "logs"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("x"), 0o644))
			},
			want: true,
		},
		{
			name: "only hidden file (no logs)",
			setup: func(dir string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, ".ttl"), []byte("x"), 0o644))
			},
			want: false,
		},
		{
			name: "logs as a regular file not a directory",
			setup: func(dir string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "logs"), []byte("x"), 0o644))
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log, _ := loggertest.New(t.Name())
			dir := t.TempDir()
			tc.setup(dir)
			assert.Equal(t, tc.want, hasOnlyLogs(log, dir))
		})
	}

	t.Run("ReadDir error returns false", func(t *testing.T) {
		log, _ := loggertest.New(t.Name())
		assert.False(t, hasOnlyLogs(log, filepath.Join(t.TempDir(), "nonexistent")))
	})
}
