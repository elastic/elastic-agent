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
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// adsStreamName is the NTFS alternate data stream the primary data stream
// is renamed to before marking the file for deletion.
const adsStreamName = ":agentrm"

// fileRenameInfo mirrors FILE_RENAME_INFO from <fileapi.h>. On 64-bit
// Windows the layout is:
//
//	Flags[4] (ReplaceIfExists/Flags union) + implicit pad[4]
//	+ RootDirectory[8] + FileNameLength[4] + FileName[N*2]
//
// Go inserts 4 bytes of implicit padding between Flags and RootDirectory
// to satisfy uintptr alignment, matching the C layout exactly. FileName is
// sized to fit adsStreamName.
type fileRenameInfo struct {
	Flags          uint32  // 0 = don't replace if destination exists
	RootDirectory  uintptr // NULL = rename within the same file (stream rename)
	FileNameLength uint32  // length of FileName in bytes, excluding null terminator
	FileName       [len(adsStreamName)]uint16
}

// fileDispositionInfo mirrors FILE_DISPOSITION_INFO from <fileapi.h>.
type fileDispositionInfo struct {
	DeleteFile uint8 // BOOLEAN: 1 = mark for deletion on close
}

func isBlockingOnExe(err error) bool {
	if err == nil {
		return false
	}
	path, errno := getPathFromError(err)
	if path == "" {
		return false
	}
	return errno == syscall.ERROR_ACCESS_DENIED
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	path, errno := getPathFromError(err)
	if path == "" {
		return false
	}
	return errno == syscall.ERROR_ACCESS_DENIED || errno == windows.ERROR_SHARING_VIOLATION
}

// removeBlockingExe applies the "ADS trick" to delete a file blocked by a
// running executable. RemovePath calls this when os.RemoveAll fails with
// ERROR_ACCESS_DENIED on an image-mapped file.
//
// The trick:
//
//  1. Open the file with DELETE access. The Windows image loader opens
//     executables with FILE_SHARE_DELETE, so this succeeds even while
//     the process is running.
//  2. Rename the primary data stream to the alternate data stream
//     adsStreamName via SetFileInformationByHandle with FileRenameInfo.
//     This severs the directory entry from the running image content.
//  3. Mark the file for deletion via SetFileInformationByHandle with
//     FileDispositionInfo (class 4). Class 4 takes the legacy
//     FileDispositionInformation code path which does NOT perform the
//     image-section check that FileDispositionInformationEx (class 64,
//     used by Go 1.25+ os.RemoveAll) does.
//
// Rename and dispose must be issued on the same handle: closing it in
// between makes dispose fail with ACCESS DENIED because the kernel re-applies
// the image-section check on a freshly opened handle.
func removeBlockingExe(blockingErr error) error {
	path, _ := getPathFromError(blockingErr)
	if path == "" {
		return fmt.Errorf("could not determine blocked path from error: %w", blockingErr)
	}

	h, err := openWithDeleteAccess(path)
	if err != nil {
		return fmt.Errorf("open %q with DELETE access: %w", path, err)
	}
	defer windows.CloseHandle(h) //nolint:errcheck // best-effort close

	if err := renameToADS(h); err != nil {
		return fmt.Errorf("rename %q to ADS: %w", path, err)
	}
	if err := markDeleteOnClose(h); err != nil {
		return fmt.Errorf("mark %q for delete-on-close: %w", path, err)
	}
	return nil
}

// getPathFromError extracts the file path and underlying syscall.Errno from
// a *fs.PathError. Returns ("", 0) if blockingErr is not a *fs.PathError
// wrapping a syscall.Errno.
func getPathFromError(blockingErr error) (string, syscall.Errno) {
	var perr *fs.PathError
	if errors.As(blockingErr, &perr) {
		var errno syscall.Errno
		if errors.As(perr.Err, &errno) {
			return perr.Path, errno
		}
	}
	return "", 0
}

// openWithDeleteAccess opens the file at path with DELETE access. Full
// share flags match what the Windows image loader uses for executables,
// so this succeeds even while the process is running.
func openWithDeleteAccess(path string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		pathPtr,
		windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
}

// renameToADS renames the primary data stream of the open file to the
// alternate data stream named adsStreamName. If a previous deletion left
// the file system with that stream still present, this call returns
// ERROR_OBJECT_NAME_COLLISION; the caller surfaces that error so it can
// be logged and retried at a higher level rather than silently swallowed.
func renameToADS(h windows.Handle) error {
	name, err := windows.UTF16FromString(adsStreamName)
	if err != nil {
		return err
	}
	// UTF16FromString appends a null terminator; FileNameLength is in
	// bytes excluding it.
	name = name[:len(name)-1]

	info := fileRenameInfo{
		// len(name) is bounded by len(adsStreamName); the multiplication
		// and conversion can never overflow uint32.
		FileNameLength: uint32(len(name) * 2), //nolint:gosec // G115 bounded by adsStreamName length
	}
	copy(info.FileName[:], name)

	return windows.SetFileInformationByHandle(
		h,
		windows.FileRenameInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}

// markDeleteOnClose marks the open file handle for deletion via
// SetFileInformationByHandle with FileDispositionInfo (class 4). Class 4
// takes the legacy FileDispositionInformation code path which does NOT
// perform the image-section check, making it safe on running executables
// — unlike FileDispositionInformationEx (class 64) used by Go 1.25+
// os.RemoveAll.
func markDeleteOnClose(h windows.Handle) error {
	info := fileDispositionInfo{DeleteFile: 1}
	return windows.SetFileInformationByHandle(
		h,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
}

// killNoneChildProcess provides a way of killing a process that is not started as a child of this process.
//
// On Windows when running in unprivileged mode the internal way that golang uses DuplicateHandle to perform the kill
// only works when the process is a child of this process.
func killNoneChildProcess(proc *os.Process) error {
	h, e := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(proc.Pid)) //nolint:gosec // G115 Conversion from int to uint32 is safe here.
	if e != nil {
		return os.NewSyscallError("OpenProcess", e)
	}
	defer func() {
		_ = syscall.CloseHandle(h)
	}()
	e = syscall.TerminateProcess(h, 1)
	return os.NewSyscallError("TerminateProcess", e)
}
