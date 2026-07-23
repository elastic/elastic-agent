// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

func TestWatcherMarkerMatchesUpgrade(t *testing.T) {
	updatedOn := time.Now().Add(-time.Minute)
	completedAt := time.Now()

	baseMarker := upgrade.UpdateMarker{
		Version:     "8.5.0",
		PrevVersion: "8.4.0",
		UpdatedOn:   updatedOn,
	}
	baseWM := &upgrade.WatcherMarker{
		TargetVersion:   "8.5.0",
		PreviousVersion: "8.4.0",
		CompletedAt:     completedAt,
	}

	t.Run("matches on version tuple and timestamp", func(t *testing.T) {
		assert.True(t, watcherMarkerMatchesUpgrade(baseWM, baseMarker))
	})

	t.Run("rejects different target version", func(t *testing.T) {
		wm := *baseWM
		wm.TargetVersion = "8.6.0"
		assert.False(t, watcherMarkerMatchesUpgrade(&wm, baseMarker))
	})

	t.Run("rejects different previous version", func(t *testing.T) {
		wm := *baseWM
		wm.PreviousVersion = "8.3.0"
		assert.False(t, watcherMarkerMatchesUpgrade(&wm, baseMarker))
	})

	t.Run("rejects when CompletedAt is before UpdatedOn", func(t *testing.T) {
		wm := *baseWM
		wm.CompletedAt = updatedOn.Add(-time.Second)
		assert.False(t, watcherMarkerMatchesUpgrade(&wm, baseMarker))
	})

	t.Run("matches when watcher marker has ActionID but marker has none", func(t *testing.T) {
		wm := *baseWM
		wm.ActionID = "action-A"
		// marker.Action == nil → GetActionID() == "" → one side empty, no constraint
		assert.True(t, watcherMarkerMatchesUpgrade(&wm, baseMarker))
	})

	t.Run("matches when both ActionIDs agree", func(t *testing.T) {
		wm := *baseWM
		wm.ActionID = "action-A"
		marker := baseMarker
		marker.Action = &fleetapi.ActionUpgrade{ActionID: "action-A"}
		assert.True(t, watcherMarkerMatchesUpgrade(&wm, marker))
	})

	t.Run("rejects when both ActionIDs differ (retry of same version)", func(t *testing.T) {
		wm := *baseWM
		wm.ActionID = "action-A"
		marker := baseMarker
		marker.Action = &fleetapi.ActionUpgrade{ActionID: "action-B"}
		assert.False(t, watcherMarkerMatchesUpgrade(&wm, marker))
	})
}

func TestUpgradeDetailsFromMarkerUpdate(t *testing.T) {
	log, _ := loggertest.New(t.Name())

	updatedOn := time.Now().Add(-time.Minute)
	completedAt := time.Now()

	baseMarker := upgrade.UpdateMarker{
		Version:     "8.5.0",
		PrevVersion: "8.4.0",
		UpdatedOn:   updatedOn,
	}

	// --- Upgrade marker still present (write events) ---

	t.Run("returns marker details directly for active state (no watcher marker read)", func(t *testing.T) {
		dataDir := t.TempDir()
		det := details.NewDetails("8.5.0", details.StateWatching, "action-1")
		marker := baseMarker
		marker.Details = det
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		assert.Equal(t, det, result)
	})

	t.Run("returns marker details for StateCompleted write event (marker still present)", func(t *testing.T) {
		// The watcher writes StateCompleted to the upgrade marker before deleting
		// it. Fleet should observe UPG_COMPLETED from this write event.
		dataDir := t.TempDir()
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateCompleted,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			CompletedAt:     completedAt,
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		det := details.NewDetails("8.5.0", details.StateCompleted, "action-1")
		marker := baseMarker
		marker.Details = det
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		// marker.Details is authoritative while the marker exists
		assert.Equal(t, det, result)
	})

	// --- Upgrade marker gone (remove event: marker.Details == nil) ---

	t.Run("returns nil when marker removed and no watcher marker", func(t *testing.T) {
		dataDir := t.TempDir()
		marker := baseMarker // Details == nil
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		assert.Nil(t, result)
	})

	t.Run("returns nil for matched completed watcher marker on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateCompleted,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			CompletedAt:     completedAt,
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		marker := baseMarker // Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		assert.Nil(t, result)
	})

	t.Run("returns rollback details from watcher marker on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateRollback,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			Reason:          "watch failed",
			CompletedAt:     completedAt,
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		marker := baseMarker // Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		require.NotNil(t, result)
		assert.Equal(t, details.StateRollback, result.State)
		assert.Equal(t, "watch failed", result.Metadata.Reason)
		assert.Equal(t, "8.5.0", result.TargetVersion)
	})

	t.Run("returns failed details with error message from watcher marker on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateFailed,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			ErrorMsg:        "rollback mechanics failed",
			CompletedAt:     completedAt,
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		marker := baseMarker // Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		require.NotNil(t, result)
		assert.Equal(t, details.StateFailed, result.State)
		assert.Equal(t, "rollback mechanics failed", result.Metadata.ErrorMsg)
	})

	t.Run("returns nil when watcher marker is stale on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		// wm.CompletedAt before marker.UpdatedOn → stale, does not match
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateRollback,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			Reason:          "old failure",
			CompletedAt:     updatedOn.Add(-time.Second),
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		marker := baseMarker // Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		// stale watcher marker → no match → nil (upgrade cleared)
		assert.Nil(t, result)
	})

	t.Run("returns nil when watcher marker ActionID mismatches on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		wm := &upgrade.WatcherMarker{
			Outcome:         details.StateRollback,
			TargetVersion:   "8.5.0",
			PreviousVersion: "8.4.0",
			ActionID:        "action-old",
			Reason:          "old failure",
			CompletedAt:     completedAt,
		}
		require.NoError(t, upgrade.WriteWatcherMarker(log, dataDir, wm))
		marker := baseMarker
		marker.Action = &fleetapi.ActionUpgrade{ActionID: "action-new"}
		// Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		// ActionID mismatch: stale watcher marker from a previous retry
		assert.Nil(t, result)
	})

	t.Run("returns nil on watcher marker load error on remove event", func(t *testing.T) {
		dataDir := t.TempDir()
		wmPath := filepath.Join(dataDir, ".watcher-marker")
		require.NoError(t, os.WriteFile(wmPath, []byte("not: valid: yaml: [[["), 0600))
		marker := baseMarker // Details == nil (remove event)
		result := upgradeDetailsFromMarkerUpdate(log, marker, dataDir)
		assert.Nil(t, result)
	})
}
