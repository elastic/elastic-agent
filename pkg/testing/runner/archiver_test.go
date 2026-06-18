// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package runner

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateRepoZipArchivePreservesMode verifies that file modes — in particular
// the executable bit — survive the repo archiving. A dropped exec bit surfaces
// remotely as "permission denied" when, e.g., a Dockerfile entrypoint script built
// from the copied tree is executed.
func TestCreateRepoZipArchivePreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable permission bits are not supported on Windows")
	}
	_, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "git %v failed: %s", args, out)
	}
	git("init")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte("data\n"), 0o644))
	git("add", "-A")

	dest := filepath.Join(t.TempDir(), "repo.zip")
	require.NoError(t, createRepoZipArchive(t.Context(), dir, dest), "createRepoZipArchive")

	zr, err := zip.OpenReader(dest)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, zr.Close())
	})

	modes := map[string]os.FileMode{}
	for _, f := range zr.File {
		modes[f.Name] = f.Mode()
	}

	m, ok := modes["run.sh"]
	require.True(t, ok, "run.sh missing from archive")
	assert.NotZero(t, m&0o111, "run.sh archive mode = %v, expected executable bits set", m)

	m, ok = modes["data.txt"]
	require.True(t, ok, "data.txt missing from archive")
	assert.Zero(t, m&0o111, "data.txt archive mode = %v, expected no executable bits", m)
}
