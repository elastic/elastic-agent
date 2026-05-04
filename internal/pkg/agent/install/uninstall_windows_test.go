// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/otiai10/copy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/logp"
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
	err = RemovePath(logp.NewNopLogger(), destDir)
	assert.NoError(t, err)
	_, err = os.Stat(destDir)
	assert.ErrorIsf(t, err, fs.ErrNotExist, "path %q still exists after removal", destDir)
}

// TestRemoveBlockingExe_DeletesRunningExecutable asserts that removeBlockingExe
// can delete a running executable when invoked with the access-denied error
// returned by Go 1.25+ os.RemoveAll.
//
// NOTE: This test is quite similar to TestRemovePath, but looks at the returned
// error codes in detail and verifies that the markDeleteOnClose call actually
// succeeds. The intent is to verify what exact effect removeBlockingExe has on
// the file it removes.
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

// pathErr builds the specific *fs.PathError shape that os.RemoveAll on
// Windows produces, so error-classification tests match production input.
func pathErr(path string, errno syscall.Errno) error {
	return &fs.PathError{Op: "remove", Path: path, Err: errno}
}

func TestIsBlockingOnExe(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                             {nil, false},
		"plain error":                     {errors.New("plain"), false},
		"PathError with ACCESS_DENIED":    {pathErr(`C:\foo.exe`, syscall.ERROR_ACCESS_DENIED), true},
		"PathError with SHARING":          {pathErr(`C:\foo.exe`, windows.ERROR_SHARING_VIOLATION), false},
		"PathError with FILE_NOT_FOUND":   {pathErr(`C:\foo.exe`, syscall.ERROR_FILE_NOT_FOUND), false},
		"PathError with non-Errno":        {&fs.PathError{Op: "remove", Path: `C:\foo.exe`, Err: errors.New("inner")}, false},
		"PathError with empty path":       {pathErr("", syscall.ERROR_ACCESS_DENIED), false},
		"wrapped PathError ACCESS_DENIED": {fmt.Errorf("ctx: %w", pathErr(`C:\foo.exe`, syscall.ERROR_ACCESS_DENIED)), true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, isBlockingOnExe(tt.err))
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                            {nil, false},
		"plain error":                    {errors.New("plain"), false},
		"ACCESS_DENIED is retryable":     {pathErr(`C:\foo.exe`, syscall.ERROR_ACCESS_DENIED), true},
		"SHARING_VIOLATION is retryable": {pathErr(`C:\foo.exe`, windows.ERROR_SHARING_VIOLATION), true},
		"FILE_NOT_FOUND is not":          {pathErr(`C:\foo.exe`, syscall.ERROR_FILE_NOT_FOUND), false},
		"empty path is not":              {pathErr("", syscall.ERROR_ACCESS_DENIED), false},
		"PathError with non-Errno":       {&fs.PathError{Op: "remove", Path: `C:\foo.exe`, Err: errors.New("inner")}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRetryableError(tt.err))
		})
	}
}

func TestGetPathFromError(t *testing.T) {
	tests := map[string]struct {
		err       error
		wantPath  string
		wantErrno syscall.Errno
	}{
		"nil": {
			err:       nil,
			wantPath:  "",
			wantErrno: 0,
		},
		"plain error": {
			err:       errors.New("plain"),
			wantPath:  "",
			wantErrno: 0,
		},
		"PathError with Errno": {
			err:       pathErr(`C:\foo.exe`, syscall.ERROR_ACCESS_DENIED),
			wantPath:  `C:\foo.exe`,
			wantErrno: syscall.ERROR_ACCESS_DENIED,
		},
		"PathError with non-Errno": {
			err:       &fs.PathError{Op: "remove", Path: `C:\foo.exe`, Err: errors.New("inner")},
			wantPath:  "",
			wantErrno: 0,
		},
		"wrapped PathError unwraps": {
			err:       fmt.Errorf("ctx: %w", pathErr(`C:\foo.exe`, windows.ERROR_SHARING_VIOLATION)),
			wantPath:  `C:\foo.exe`,
			wantErrno: windows.ERROR_SHARING_VIOLATION,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			path, errno := getPathFromError(tt.err)
			assert.Equal(t, tt.wantPath, path)
			assert.Equal(t, tt.wantErrno, errno)
		})
	}
}

func TestOpenWithDeleteAccess(t *testing.T) {
	t.Run("succeeds on existing file and yields valid handle", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "f.txt")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

		h, err := openWithDeleteAccess(path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = windows.CloseHandle(h) })
		assert.NotEqual(t, windows.InvalidHandle, h)
	})

	t.Run("returns InvalidHandle and error for missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.txt")
		h, err := openWithDeleteAccess(path)
		require.Error(t, err)
		assert.Equal(t, windows.InvalidHandle, h)
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})

	t.Run("share flags allow concurrent read by another opener", func(t *testing.T) {
		// openWithDeleteAccess shares READ|WRITE|DELETE so the Windows
		// image loader (which opens running images with the same share
		// mode) can keep the file mapped while we hold a DELETE-access
		// handle. The new opener also has to share DELETE — without
		// that, share-mode rules block it because our existing handle
		// holds DELETE access.
		path := filepath.Join(t.TempDir(), "f.txt")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

		h, err := openWithDeleteAccess(path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = windows.CloseHandle(h) })

		pathPtr, err := windows.UTF16PtrFromString(path)
		require.NoError(t, err)
		h2, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		require.NoError(t, err)
		_ = windows.CloseHandle(h2)
	})
}

// TestRenameToADS_MovesPrimaryStreamToADS verifies that after the rename
// the primary data stream of the file is empty and the original content
// has moved to the :agentrm alternate data stream.
func TestRenameToADS_MovesPrimaryStreamToADS(t *testing.T) {
	const original = "hello world"
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	h, err := openWithDeleteAccess(path)
	require.NoError(t, err)

	require.NoError(t, renameToADS(h))
	// Close the handle before reading. After the rename, the handle
	// is associated with the :agentrm stream, and os.ReadFile uses a
	// share mode that does not include FILE_SHARE_DELETE — so any
	// read of :agentrm would conflict with our still-open DELETE
	// handle. Closing here is safe: no delete-pending was set.
	require.NoError(t, windows.CloseHandle(h))

	// The directory entry remains; the primary stream is now empty.
	primary, err := os.ReadFile(path)
	require.NoError(t, err, "primary stream should still be readable after rename")
	assert.Empty(t, primary, "primary stream should be empty after rename")

	// The original content is reachable via the :agentrm ADS.
	ads, err := os.ReadFile(path + ":agentrm")
	require.NoError(t, err, ":agentrm ADS should be readable after rename")
	assert.Equal(t, original, string(ads), ":agentrm ADS should hold original content")
}

// TestRenameToADS_NameCollision verifies that if the :agentrm stream
// already exists (e.g. from an earlier failed deletion), renameToADS
// surfaces an ErrExist-compatible error rather than silently overwriting.
// This is the property RemovePath relies on to log and continue.
func TestRenameToADS_NameCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("primary"), 0o644))
	// Pre-populate the target ADS so the rename collides.
	require.NoError(t, os.WriteFile(path+":agentrm", []byte("leftover"), 0o644))

	h, err := openWithDeleteAccess(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = windows.CloseHandle(h) })

	err = renameToADS(h)
	require.Error(t, err, "expected rename to fail when :agentrm already exists")
	t.Logf("rename collision error: %v", err)
	assert.ErrorIs(t, err, fs.ErrExist,
		"expected ErrExist-compatible Win32 error, got %v", err)
}

// TestMarkDeleteOnClose_RemovesFileOnClose verifies the directory entry
// is gone after the marked handle closes (no other handles holding the
// file open).
func TestMarkDeleteOnClose_RemovesFileOnClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))

	h, err := openWithDeleteAccess(path)
	require.NoError(t, err)

	require.NoError(t, markDeleteOnClose(h))
	// File still exists while a handle is open with delete-pending set.
	// We can't open it (Windows returns ACCESS_DENIED for
	// delete-pending files), but the directory entry is still
	// enumerable until the last handle closes.
	require.True(t, dirContains(t, dir, "f.txt"),
		"file should still appear in directory listing while handle is open")

	require.NoError(t, windows.CloseHandle(h))

	_, statErr := os.Lstat(path)
	assert.ErrorIs(t, statErr, fs.ErrNotExist,
		"file should be gone after the delete-pending handle closes")
}

// dirContains reports whether dir has an entry named name. Used to
// observe a file that is in delete-pending state, where a direct stat
// or open would fail with ACCESS_DENIED.
func dirContains(t *testing.T, dir, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.Name() == name {
			return true
		}
	}
	return false
}

// TestRenameAndDispose_FullCycle exercises the full removeBlockingExe
// sequence on an ordinary file (no running image): open, rename, dispose,
// close. The handle is on the renamed :agentrm stream when the dispose
// flag is set, so closing the handle deletes only that named stream —
// the directory entry (with an empty primary stream) is preserved on
// NTFS. This matches what RemovePath relies on: a follow-up
// os.RemoveAll then succeeds because the primary stream is no longer
// backed by an image section. See also TestRemoveBlockingExe_DeletesRunningExecutable.
func TestRenameAndDispose_FullCycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("content"), 0o644))

	h, err := openWithDeleteAccess(path)
	require.NoError(t, err)

	require.NoError(t, renameToADS(h))
	require.NoError(t, markDeleteOnClose(h))
	require.NoError(t, windows.CloseHandle(h))

	// Directory entry with empty primary stream is preserved.
	primary, err := os.ReadFile(path)
	require.NoError(t, err, "file should still exist after close (only the ADS is deleted)")
	assert.Empty(t, primary, "primary stream should be empty")

	// The :agentrm ADS is gone — that's the stream the handle was on.
	_, err = os.Lstat(path + ":agentrm")
	assert.ErrorIs(t, err, fs.ErrNotExist, ":agentrm ADS should be gone")

	// And RemovePath can now finish the job: with no image section on
	// the empty primary stream, os.RemoveAll succeeds.
	require.NoError(t, os.RemoveAll(path))
}

// TestRemoveBlockingExe_NoPathInError verifies that an error which does
// not carry a *fs.PathError is reported back to the caller (so RemovePath
// logs it) rather than silently swallowed.
func TestRemoveBlockingExe_NoPathInError(t *testing.T) {
	err := removeBlockingExe(errors.New("not a PathError"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine blocked path")
}

// TestRemoveBlockingExe_FileMissing verifies that openWithDeleteAccess
// failure (for a path that does not exist) is wrapped with the path
// rather than returned bare.
func TestRemoveBlockingExe_FileMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.exe")
	err := removeBlockingExe(pathErr(missing, syscall.ERROR_ACCESS_DENIED))
	require.Error(t, err)
	// removeBlockingExe formats the path with %q, so search for the
	// quoted form (backslashes Go-escaped) rather than the raw path.
	assert.Contains(t, err.Error(), strconv.Quote(missing))
	assert.ErrorIs(t, err, fs.ErrNotExist)
}
