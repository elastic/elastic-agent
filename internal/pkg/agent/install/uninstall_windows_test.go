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

	"github.com/elastic/elastic-agent-libs/logp"
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
// a directory containing a running executable (or schedules leftovers for
// reboot deletion and returns nil).
func TestRemovePath(t *testing.T) {
	destDir := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	startBlockingExe(t, destDir)

	err := RemovePath(logp.L(), destDir)
	assert.NoError(t, err)
}

// TestRenameRunningExe verifies that os.Rename works on a running executable.
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

	// Move the exe outside the directory.
	tmpPath := filepath.Join(tmpDir, ".test-rm.exe")
	err = os.Rename(exePath, tmpPath)
	require.NoError(t, err)

	// Now RemoveAll succeeds.
	err = os.RemoveAll(destDir)
	assert.NoError(t, err, "RemoveAll should succeed after moving the exe out")

	_, err = os.Stat(destDir)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// TestScheduleDeleteOnReboot verifies that scheduleDeleteOnReboot renames the
// blocked executable in place with the leftover prefix and keeps it in the
// same directory.
func TestScheduleDeleteOnReboot(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	_, exePath := startBlockingExe(t, destDir)

	blockingErr := makeBlockingError(exePath)
	err := scheduleDeleteOnReboot(logp.L(), blockingErr, destDir)
	require.NoError(t, err)

	// The original path should be gone (renamed).
	_, err = os.Stat(exePath)
	assert.ErrorIs(t, err, fs.ErrNotExist, "original exe path should no longer exist")

	// A file with the leftover prefix should exist in the same directory.
	entries, err := os.ReadDir(destDir)
	require.NoError(t, err)

	var found bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), leftoverPrefix) {
			found = true
			break
		}
	}
	assert.True(t, found, "renamed file with prefix %q should exist in %s", leftoverPrefix, destDir)
}

// TestRemoveAllDeletesEverythingExceptBlockingExe verifies that os.RemoveAll
// deletes all files it can and only fails on the running exe.
func TestRemoveAllDeletesEverythingExceptBlockingExe(t *testing.T) {
	tmpDir := t.TempDir()
	destDir := filepath.Join(tmpDir, "target")
	require.NoError(t, os.Mkdir(destDir, 0o755))

	// Create some additional files alongside the exe.
	require.NoError(t, os.WriteFile(filepath.Join(destDir, "config.yml"), []byte("test"), 0o644))
	subDir := filepath.Join(destDir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "data.txt"), []byte("test"), 0o644))

	_, exePath := startBlockingExe(t, destDir)

	// RemoveAll should fail on the exe but delete everything else.
	err := os.RemoveAll(destDir)
	require.Error(t, err, "RemoveAll should fail due to running exe")

	// The exe should still exist.
	_, err = os.Stat(exePath)
	assert.NoError(t, err, "exe should still exist")

	// Other files should be gone.
	_, err = os.Stat(filepath.Join(destDir, "config.yml"))
	assert.ErrorIs(t, err, fs.ErrNotExist, "config.yml should be deleted")

	_, err = os.Stat(filepath.Join(subDir, "data.txt"))
	assert.ErrorIs(t, err, fs.ErrNotExist, "data.txt should be deleted")
}

// makeBlockingError constructs an error matching what os.RemoveAll produces
// on Windows when it cannot delete a file due to a running exe.
func makeBlockingError(path string) error {
	return &fs.PathError{Op: "unlinkat", Path: path, Err: syscall.ERROR_ACCESS_DENIED}
}
