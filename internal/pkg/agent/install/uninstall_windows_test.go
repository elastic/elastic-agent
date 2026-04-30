// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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
	cmd := exec.CommandContext(t.Context(), destpath)
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
// NOTE: This test is quite similar to TestRemovePath, but looks at the returned
// error codes in detail and verifies that the disposeHandle call actually succeeds.
// The intent is to verify what exact effect removeBlockingExe has on the file
// it removes.
//
// For more background, see https://github.com/elastic/elastic-agent/issues/13156.
// This test reproduces integration test failures encountered in that issue.
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

	cmd := exec.CommandContext(t.Context(), destpath)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Trigger the access-denied error.
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
	require.Equal(t, syscall.ERROR_ACCESS_DENIED, errno,
		"expected ERROR_ACCESS_DENIED, got %v", errno)
	require.True(t, isBlockingOnExe(rmErr), "isBlockingOnExe should classify this error as blocking")

	require.NoError(t, removeBlockingExe(rmErr), "removeBlockingExe failed")

	// Reproduce, step by step, the call sequence that Go 1.25's
	// removefileat (used by os.RemoveAll during its per-entry directory
	// walk) issues for this file, and assert each step.

	// (1) NtCreateFile (FILE_OPEN with DELETE access). The rename trick
	// moves the file's primary stream to an alternate data stream, but
	// the directory entry itself is preserved on NTFS, so this open
	// succeeds. Same flags as internal/syscall/windows.Deleteat's
	// NtOpenFile call.
	h, openStatus := openExeLikeRemoveAll(t, destpath)
	require.NoError(t, openStatus, "NtCreateFile after removeBlockingExe failed")
	t.Cleanup(func() {
		_ = windows.CloseHandle(h)
	})

	// (2) NtSetInformationFile with FileDispositionInformationEx and
	// FILE_DISPOSITION_DELETE | POSIX_SEMANTICS |
	// FORCE_IMAGE_SECTION_CHECK | IGNORE_READONLY_ATTRIBUTE -- the
	// exact flag combination Deleteat uses. Before removeBlockingExe
	// this call fails with STATUS_CANNOT_DELETE because the .exe is
	// mapped as an image section by the running process. After
	// removeBlockingExe's rename moves the primary stream to an ADS,
	// the image section is no longer associated with the directory
	// entry's primary stream and the check passes.
	require.NoError(t, disposeLikeRemoveAll(h),
		"FileDispositionInformationEx with FORCE_IMAGE_SECTION_CHECK must succeed after removeBlockingExe")

	// (3) Closing the handle commits the deletion. POSIX_SEMANTICS
	// removes the directory entry now even though the loader still
	// has the image section mapped.
	require.NoError(t, windows.CloseHandle(h), "CloseHandle")

	// And the delete must actually take effect: a follow-up
	// os.RemoveAll on the file path returns nil because the entry is
	// gone. With the previous close-and-reopen removeBlockingExe the
	// rename never took effect, the image-section check at step (2)
	// kept failing, and this call would keep returning
	// ERROR_ACCESS_DENIED.
	require.NoError(t, os.RemoveAll(destpath),
		"os.RemoveAll(%q) failed after removeBlockingExe + dispose", destpath)
}

// openExeLikeRemoveAll opens path the same way Go 1.25's removefileat
// (in os/root_windows.go -> internal/syscall/windows.Deleteat) opens an
// entry during os.RemoveAll's directory walk. Returns the resulting
// handle and the raw NTSTATUS.
//
// We use NtCreateFile with FILE_OPEN disposition rather than NtOpenFile
// because NtOpenFile is not exposed by golang.org/x/sys/windows; the two
// are functionally equivalent for FILE_OPEN.
func openExeLikeRemoveAll(t *testing.T, path string) (windows.Handle, error) {
	t.Helper()

	parentDir, base := filepath.Split(path)
	parentDir = strings.TrimRight(parentDir, `\/`)

	parentW, err := windows.UTF16PtrFromString(parentDir)
	require.NoError(t, err)
	parent, err := windows.CreateFile(
		parentW,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	require.NoError(t, err, "open parent dir %q", parentDir)
	t.Cleanup(func() {
		assert.NoError(t, windows.CloseHandle(parent))
	})

	objectName, err := windows.NewNTUnicodeString(base)
	require.NoError(t, err)
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: parent,
		ObjectName:    objectName,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))

	var iosb windows.IO_STATUS_BLOCK
	var h windows.Handle
	status := windows.NtCreateFile(
		&h,
		windows.FILE_READ_ATTRIBUTES|windows.DELETE,
		oa, &iosb, nil, 0,
		windows.FILE_SHARE_DELETE|windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT,
		0, 0,
	)
	return h, status
}

// disposeLikeRemoveAll issues the FileDispositionInformationEx call that
// Go 1.25's Deleteat issues on the per-entry handle during RemoveAll's
// directory walk: DELETE | POSIX_SEMANTICS | FORCE_IMAGE_SECTION_CHECK |
// IGNORE_READONLY_ATTRIBUTE. FILE_DISPOSITION_INFORMATION_EX is a single
// ULONG of flags, so a uint32 buffer is the whole structure.
//
// On older Windows (e.g. Server 2016) FileDispositionInformationEx (or
// one of its flags) is not supported; in that case Go's Deleteat falls
// back to the legacy FileDispositionInfo via deleteatFallback, and we
// do the same here so the test exercises the same path on every
// supported OS.
func disposeLikeRemoveAll(h windows.Handle) error {
	flags := uint32(
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_POSIX_SEMANTICS |
			windows.FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	)
	var iosb windows.IO_STATUS_BLOCK
	err := windows.NtSetInformationFile(
		h,
		&iosb,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
		windows.FileDispositionInformationEx,
	)
	var status windows.NTStatus
	if errors.As(err, &status) {
		switch status {
		case windows.STATUS_INVALID_INFO_CLASS,
			windows.STATUS_INVALID_PARAMETER,
			windows.STATUS_NOT_SUPPORTED:
			return setLegacyDispositionDelete(h)
		}
	}
	return err
}

// setLegacyDispositionDelete sets DeleteFile=true via the legacy
// FileDispositionInfo info class. FILE_DISPOSITION_INFO is a single
// BOOLEAN (1 byte). Used as the fallback when FileDispositionInformationEx
// is not supported, matching Go's deleteatFallback.
func setLegacyDispositionDelete(h windows.Handle) error {
	deleteFile := uint8(1)
	return windows.SetFileInformationByHandle(
		h,
		windows.FileDispositionInfo,
		&deleteFile,
		uint32(unsafe.Sizeof(deleteFile)),
	)
}
