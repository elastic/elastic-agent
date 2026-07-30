// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAckMarker_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	am := &AckMarker{
		ActionID: "test-action-id",
		AckedAt:  now,
	}

	require.NoError(t, WriteAckMarker(dir, am))

	got, err := LoadAckMarker(dir)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, am.ActionID, got.ActionID)
	assert.Equal(t, am.AckedAt, got.AckedAt)
}

func TestAckMarker_MissingFileIsNil(t *testing.T) {
	dir := t.TempDir()

	got, err := LoadAckMarker(dir)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestAckMarker_Overwrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	first := &AckMarker{ActionID: "action-1", AckedAt: now}
	require.NoError(t, WriteAckMarker(dir, first))

	second := &AckMarker{ActionID: "action-2", AckedAt: now.Add(time.Minute)}
	require.NoError(t, WriteAckMarker(dir, second))

	got, err := LoadAckMarker(dir)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "action-2", got.ActionID)
}
