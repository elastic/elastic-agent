// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	cp "github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startBlockingExe copies the testblocking binary into destDir and starts it.
// Returns the exec.Cmd and the path to the running exe.
func startBlockingExe(t *testing.T, destDir string) (*exec.Cmd, string) {
	t.Helper()

	const (
		pkgName    = "testblocking"
		binaryName = pkgName + ".exe"
	)

	destpath, err := filepath.Abs(filepath.Join(destDir, binaryName))
	require.NoError(t, err)

	srcPath, err := filepath.Abs(filepath.Join(pkgName, binaryName))
	require.NoError(t, err)

	err = cp.Copy(srcPath, destpath, cp.Options{Sync: true})
	require.NoError(t, err)

	cmd := exec.CommandContext(t.Context(), destpath)
	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		// The process is killed automatically by CommandContext when the test
		// context ends, so Kill may return "Access is denied" and Wait may
		// return a non-zero exit code. We just need to reap the process.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	return cmd, destpath
}

// TestRemovePath verifies the full end-to-end: RemovePath successfully removes
// a directory containing a running executable.
func TestRemovePath(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	startBlockingExe(t, destDir)

	err := RemovePath(destDir)
	assert.NoError(t, err)
	_, err = os.Stat(destDir)
	assert.ErrorIsf(t, err, fs.ErrNotExist, "path %q still exists after removal", destDir)
}

// TestRenameRunningExe verifies that os.Rename works on a running executable,
// which is the core assumption behind removeBlockingExe.
func TestRenameRunningExe(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	_, exePath := startBlockingExe(t, destDir)

	// Verify the exe cannot be deleted while running.
	err := os.Remove(exePath)
	require.Error(t, err, "os.Remove should fail on a running exe")

	// But it can be renamed.
	tmpPath := exePath + ".moved"
	err = os.Rename(exePath, tmpPath)
	assert.NoError(t, err, "os.Rename should succeed on a running exe")

	// The original path no longer exists.
	_, err = os.Stat(exePath)
	assert.ErrorIs(t, err, fs.ErrNotExist)

	// The process is still running (rename doesn't kill it).
	// The moved file exists at the new path.
	_, err = os.Stat(tmpPath)
	assert.NoError(t, err, "moved file should exist at new path")
}

// TestRemoveAllSucceedsAfterRename verifies that once the running exe is
// moved out of the directory, os.RemoveAll can clean it up.
func TestRemoveAllSucceedsAfterRename(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	_, exePath := startBlockingExe(t, destDir)

	// RemoveAll fails while the exe is inside the directory.
	err := os.RemoveAll(destDir)
	require.Error(t, err, "RemoveAll should fail while running exe is in the directory")

	// Move the exe outside the directory (but inside tmpDir so t.TempDir cleans it up).
	tmpPath := filepath.Join(tmpDir, ".test-rm.exe")
	err = os.Rename(exePath, tmpPath)
	require.NoError(t, err)

	// Now RemoveAll succeeds.
	err = os.RemoveAll(destDir)
	assert.NoError(t, err, "RemoveAll should succeed after moving the exe out")

	_, err = os.Stat(destDir)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestRemoveBlockingExeMovesOutsideTree verifies that removeBlockingExe places
// the temp file in the parent of rootPath, not inside the tree being deleted.
func TestRemoveBlockingExeMovesOutsideTree(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	_, exePath := startBlockingExe(t, destDir)

	// Construct an error that matches what os.RemoveAll produces.
	blockingErr := makeBlockingError(exePath)

	err := removeBlockingExe(blockingErr, destDir)
	require.NoError(t, err, "removeBlockingExe should succeed")

	// The original path should be gone.
	_, err = os.Stat(exePath)
	assert.ErrorIs(t, err, fs.ErrNotExist, "original exe should no longer exist")

	// A temp file should exist in the parent of destDir (i.e. tmpDir).
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	var found bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".elastic-agent-rm-") && strings.HasSuffix(e.Name(), ".exe") {
			found = true
			break
		}
	}
	assert.True(t, found, "temp file should exist in parent directory")
}

// TestRemoveBlockingExeCleansTempOnFailure verifies that if os.Rename fails
// (e.g. path doesn't exist), the temp file is cleaned up.
func TestRemoveBlockingExeCleansTempOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	// Use a non-existent path so the rename will fail.
	fakePath := filepath.Join(destDir, "nonexistent.exe")
	blockingErr := makeBlockingError(fakePath)

	err := removeBlockingExe(blockingErr, destDir)
	assert.Error(t, err, "removeBlockingExe should fail when source doesn't exist")

	// No temp files should be left behind in the parent.
	entries, err := os.ReadDir(tmpDir)
	require.NoError(t, err)

	for _, e := range entries {
		assert.False(t,
			strings.HasPrefix(e.Name(), ".elastic-agent-rm-"),
			"temp file %q should have been cleaned up", e.Name())
	}
}

// makeBlockingError constructs an error matching what os.RemoveAll produces
// on Windows when it cannot delete a file due to a running exe.
func makeBlockingError(path string) error {
	return &fs.PathError{Op: "unlinkat", Path: path, Err: syscall.ERROR_ACCESS_DENIED}
}
