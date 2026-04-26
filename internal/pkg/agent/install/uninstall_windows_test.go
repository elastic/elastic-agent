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
	"syscall"
	"testing"
	"time"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemovePath(t *testing.T) {
	var (
		pkgName    = "testblocking"
		binaryName = pkgName + ".exe"
	)

	// Create a temporary directory that we can safely remove. The directory is created as a new
	// sub-directory. This avoids having Microsoft Defender quarantine the file if it is exec'd from
	// the default temporary directory.
	destDir, err := os.MkdirTemp(pkgName, t.Name())
	require.NoError(t, err)

	// Copy the test executable to the new temporary directory.
	destpath, err := filepath.Abs(filepath.Join(destDir, binaryName))
	require.NoErrorf(t, err, "failed dest abs %s + %s", destDir, binaryName)

	srcPath, err := filepath.Abs(filepath.Join(pkgName, binaryName))
	require.NoErrorf(t, err, "failed src abs %s + %s", pkgName, binaryName)

	err = copy.Copy(srcPath, destpath, copy.Options{Sync: true})
	require.NoError(t, err)

	// Execute the test executable asynchronously.
	cmd := exec.Command(destpath)
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Ensure the directory containing the executable can be removed.
	err = RemovePath(destDir)
	assert.NoError(t, err)
	_, err = os.Stat(destDir)
	assert.ErrorIsf(t, err, fs.ErrNotExist, "path %q still exists after removal", destDir)
}

// TestRemoveBlockingExe_DeletesRunningExecutable asserts that removeBlockingExe
// can delete a running executable when invoked with the access-denied error
// returned by Go 1.25+ os.RemoveAll.
//
// Background:
//
// When the project bumped to Go 1.25 (e653b4f1d2) RemovePath had to switch
// from os.RemoveAll to a re-implementation of Go 1.24's path-based RemoveAll
// (see removeAll in uninstall.go), because Go 1.25 rewrote removeall_at.go to
// use NtCreateFile + FileDispositionInformationEx with
// FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK -- a flag that makes the syscall
// fail with STATUS_CANNOT_DELETE / ERROR_ACCESS_DENIED for any file currently
// mapped as a running image. removeBlockingExe is what lets the path-based
// Go 1.24 implementation recover from those failures, by renaming the
// running binary out of the directory via the NTFS "ADS rename trick" so
// the next iteration's directory walk no longer sees it.
//
// The previous implementation of removeBlockingExe split the work across two
// distinct file handles:
//
//  1. open with DELETE access  -> rename primary stream to ":agentrm"  -> close
//  2. open with DELETE access  -> SetFileInformationByHandle(FileDispositionInfo, DeleteFile=true)  -> close
//
// That sequence works only as long as the kernel never re-evaluates the image
// section between the two NtSetInformationFile calls. Empirically, on
// Windows 11 with Go 1.25 the dispose call (step 2) returns
// STATUS_CANNOT_DELETE / ERROR_ACCESS_DENIED whenever it is performed on a
// freshly-opened handle, even after the rename succeeded. The same dispose
// call performed on the SAME handle that did the rename succeeds.
//
// This test reproduces the failure by:
//   - starting the test binary so the kernel installs an image section,
//   - calling os.RemoveAll to obtain the canonical *fs.PathError that
//     RemovePath would observe in production once we drop the Go 1.24
//     re-implementation,
//   - invoking removeBlockingExe with that error,
//   - asserting the file is actually gone afterwards.
//
// With the old close+reopen implementation the rename succeeds, the dispose
// fails with access-denied, and the file remains. With the
// keep-handle-open implementation the dispose succeeds and the file is gone
// once the handle is closed.
func TestRemoveBlockingExe_DeletesRunningExecutable(t *testing.T) {
	const (
		pkgName    = "testblocking"
		binaryName = pkgName + ".exe"
	)

	destDir, err := os.MkdirTemp(pkgName, t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(destDir) })

	destpath, err := filepath.Abs(filepath.Join(destDir, binaryName))
	require.NoError(t, err)
	srcPath, err := filepath.Abs(filepath.Join(pkgName, binaryName))
	require.NoError(t, err)

	require.NoError(t, copy.Copy(srcPath, destpath, copy.Options{Sync: true}))

	cmd := exec.Command(destpath)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Trigger the access-denied error that production code recovers from.
	// On Go 1.25+ os.RemoveAll uses unlinkat which calls NtCreateFile with
	// DELETE access; the running image section makes that fail with
	// ERROR_ACCESS_DENIED on the .exe.
	rmErr := os.RemoveAll(destDir)
	require.Error(t, rmErr, "expected os.RemoveAll to fail while exe is running")

	// Verify the precondition: the error is a PathError carrying
	// ERROR_ACCESS_DENIED on our exe path. If this ever stops being true
	// (e.g. a future Go release changes its delete strategy) the rest of the
	// test would silently no-op, so guard it.
	var perr *fs.PathError
	require.ErrorAs(t, rmErr, &perr, "expected *fs.PathError, got %T", rmErr)
	var errno syscall.Errno
	require.ErrorAs(t, perr.Err, &errno, "expected syscall.Errno in PathError.Err")
	require.Equal(t, syscall.Errno(syscall.ERROR_ACCESS_DENIED), errno,
		"expected ERROR_ACCESS_DENIED, got %v", errno)
	require.True(t, isBlockingOnExe(rmErr), "isBlockingOnExe should classify this error as blocking")

	// Drive the production recovery path.
	exeErr := removeBlockingExe(rmErr)
	t.Logf("removeBlockingExe returned: %v", exeErr)

	// Postcondition: a follow-up os.RemoveAll must now succeed end-to-end.
	// This is exactly what RemovePath's loop in uninstall.go does after
	// invoking removeBlockingExe.
	//
	// Note we don't assert on os.Lstat directly: after the ADS-rename + delete-
	// on-close trick the directory entry can linger in "delete pending" until
	// the loader's handle closes, but unlinkat treats that state as already-
	// gone. So the meaningful, RemovePath-equivalent check is RemoveAll.
	//
	// With the OLD removeBlockingExe (close + reopen between rename and
	// dispose) the dispose fails with ACCESS DENIED, the file is not even put
	// into delete-pending state, and os.RemoveAll keeps failing -> test fails.
	require.Eventually(t, func() bool {
		err := os.RemoveAll(destDir)
		return err == nil
	}, 5*time.Second, 100*time.Millisecond,
		"os.RemoveAll(%q) never succeeded after removeBlockingExe (regression: dispose failed silently)",
		destDir)
}
