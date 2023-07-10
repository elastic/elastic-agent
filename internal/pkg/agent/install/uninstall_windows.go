// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isBlockingOnExe(err error) bool {
	if err == nil {
		return false
	}
	path := getPathFromError(err)
	return path != ""
}

func removeBlockingExe(blockingErr error) (string, error) {
	path := getPathFromError(blockingErr)
	if path == "" {
		return "", nil
	}

	// open handle for delete only
	h, err := openDeleteHandle(path)
	if err != nil {
		return "", fmt.Errorf("failed to open handle for %q: %w", path, err)
	}

	// rename handle
	err = renameHandle(h)
	_ = windows.CloseHandle(h)
	if err != nil {
		return "", fmt.Errorf("failed to rename handle for %q: %w", path, err)
	}

	// re-open handle
	h, err = openDeleteHandle(path)
	if err != nil {
		return "", fmt.Errorf("failed to open handle after rename for %q: %w", path, err)
	}

	// dispose of the handle
	err = disposeHandle(h)
	_ = windows.CloseHandle(h)
	if err != nil {
		return "", fmt.Errorf("failed to dispose handle for %q: %w", path, err)
	}
	return path, nil
}

func getPathFromError(blockingErr error) string {
	var perr *fs.PathError
	if errors.As(blockingErr, &perr) {
		var errno syscall.Errno
		if errors.As(perr.Err, &errno) {
			if errno == syscall.ERROR_ACCESS_DENIED {
				return perr.Path
			}
		}
	}
	return ""
}

func openDeleteHandle(path string) (windows.Handle, error) {
	wPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(
		wPath,
		windows.DELETE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func renameHandle(hHandle windows.Handle) error {
	wRename, err := windows.UTF16FromString(":agentrm")
	if err != nil {
		return err
	}

	var rename fileRenameInfo
	lpwStream := &wRename[0]
	rename.FileNameLength = uint32(unsafe.Sizeof(lpwStream))

	_, _, _ = windows.NewLazyDLL("kernel32.dll").NewProc("RtlCopyMemory").Call(
		uintptr(unsafe.Pointer(&rename.FileName[0])),
		uintptr(unsafe.Pointer(lpwStream)),
		unsafe.Sizeof(lpwStream),
	)

	err = windows.SetFileInformationByHandle(
		hHandle,
		windows.FileRenameInfo,
		(*byte)(unsafe.Pointer(&rename)),
		uint32(unsafe.Sizeof(rename)+unsafe.Sizeof(lpwStream)),
	)
	if err != nil {
		return err
	}
	return nil
}

func disposeHandle(hHandle windows.Handle) error {
	var deleteFile fileDispositionInfo
	deleteFile.DeleteFile = true

	err := windows.SetFileInformationByHandle(
		hHandle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&deleteFile)),
		uint32(unsafe.Sizeof(deleteFile)),
	)
	if err != nil {
		return err
	}
	return nil
}

type fileRenameInfo struct {
	Union struct {
		ReplaceIfExists bool
		Flags           uint32
	}
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

type fileDispositionInfo struct {
	DeleteFile bool
}
