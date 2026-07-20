// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/elastic/elastic-agent/pkg/upgrade/details"
)

func TestLoadWatcherMarker_MissingFileIsNilNoError(t *testing.T) {
	dataDir := t.TempDir()

	wm, err := LoadWatcherMarker(dataDir)
	require.NoError(t, err)
	assert.Nil(t, wm)
}

func TestWriteAndLoadWatcherMarker_NoLoss(t *testing.T) {
	dataDir := t.TempDir()
	log, _ := loggertest.New(t.Name())

	original := &WatcherMarker{
		Outcome:         details.StateRollback,
		TargetVersion:   "8.5.0",
		PreviousVersion: "8.4.0",
		ActionID:        "action-123",
		Reason:          "watch failed",
		CompletedAt:     time.Now().Truncate(time.Second),
		WatcherVersion:  "8.5.0",
	}

	require.NoError(t, WriteWatcherMarker(log, dataDir, original))

	loaded, err := LoadWatcherMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, original.Outcome, loaded.Outcome)
	assert.Equal(t, original.TargetVersion, loaded.TargetVersion)
	assert.Equal(t, original.PreviousVersion, loaded.PreviousVersion)
	assert.Equal(t, original.ActionID, loaded.ActionID)
	assert.Equal(t, original.Reason, loaded.Reason)
	assert.Equal(t, original.ErrorMsg, loaded.ErrorMsg)
	assert.True(t, original.CompletedAt.Equal(loaded.CompletedAt))
	assert.Equal(t, original.WatcherVersion, loaded.WatcherVersion)
}

func TestWriteWatcherMarker_OverwritesPreviousRecord(t *testing.T) {
	dataDir := t.TempDir()
	log, _ := loggertest.New(t.Name())

	first := &WatcherMarker{
		Outcome:       details.StateRollback,
		TargetVersion: "8.5.0",
		CompletedAt:   time.Now().Truncate(time.Second),
	}
	require.NoError(t, WriteWatcherMarker(log, dataDir, first))

	second := &WatcherMarker{
		Outcome:       details.StateCompleted,
		TargetVersion: "8.6.0",
		CompletedAt:   first.CompletedAt.Add(time.Hour),
	}
	require.NoError(t, WriteWatcherMarker(log, dataDir, second))

	loaded, err := LoadWatcherMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, details.StateCompleted, loaded.Outcome)
	assert.Equal(t, "8.6.0", loaded.TargetVersion)
}

func TestWriteWatcherMarker_DefaultsWatcherVersion(t *testing.T) {
	dataDir := t.TempDir()
	log, _ := loggertest.New(t.Name())

	wm := &WatcherMarker{
		Outcome:       details.StateCompleted,
		TargetVersion: "8.5.0",
		CompletedAt:   time.Now(),
	}
	require.NoError(t, WriteWatcherMarker(log, dataDir, wm))

	loaded, err := LoadWatcherMarker(dataDir)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.NotEmpty(t, loaded.WatcherVersion)
}
