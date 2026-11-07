// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package workflowrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	require.NoError(t, err)
	require.NoError(t, s.Put("a1", map[string]interface{}{"result_id": "a1"}))

	reopened, err := OpenStore(dir)
	require.NoError(t, err)
	ack, ok := reopened.Get("a1")
	require.True(t, ok)
	assert.Equal(t, "a1", ack["result_id"])

	info, err := os.Stat(filepath.Join(dir, storeFileName))
	require.NoError(t, err)
	if os.PathSeparator == '/' {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestStoreExpiresOldEntries(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	require.NoError(t, err)

	now := time.Now()
	s.now = func() time.Time { return now }
	require.NoError(t, s.Put("old", map[string]interface{}{}))

	now = now.Add(storeRetention + time.Minute)
	_, ok := s.Get("old")
	assert.False(t, ok)

	require.NoError(t, s.Put("new", map[string]interface{}{}))
	assert.NotContains(t, s.entries, "old", "expired entries are pruned on write")
}

func TestStoreIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, storeFileName), []byte("{not json"), 0o600))

	s, err := OpenStore(dir)
	require.NoError(t, err)
	_, ok := s.Get("anything")
	assert.False(t, ok)
}
