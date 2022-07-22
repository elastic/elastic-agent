// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/stretchr/testify/require"
)

func setupDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	paths.SetDownloads(dir)

	err := os.WriteFile(filepath.Join(dir, "test-8.3.0-file"), []byte("hello, world!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "test-8.4.0-file"), []byte("hello, world!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "test-8.5.0-file"), []byte("hello, world!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "test-hash-file"), []byte("hello, world!"), 0600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPreUpgradeCleanup(t *testing.T) {
	setupDir(t)
	err := preUpgradeCleanup("8.4.0")
	require.NoError(t, err)

	files, err := os.ReadDir(paths.Downloads())
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "test-8.4.0-file", files[0].Name())
	fi, err := files[0].Info()
	require.NoError(t, err)
	require.Greater(t, fi.Size(), int64(0))
}

func TestCleanAllDownloads(t *testing.T) {
	setupDir(t)
	err := cleanAllDownloads()
	require.NoError(t, err)
	files, err := os.ReadDir(paths.Downloads())
	require.NoError(t, err)
	require.Len(t, files, 0)
}
