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
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

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

// removeBlockingExe moves a locked executable out of the way so that
// os.RemoveAll can remove the directory it lived in. On Windows a running exe
// cannot be deleted, but it *can* be renamed/moved (even across directories,
// as long as it stays on the same volume). After the move we schedule the temp
// file for deletion on the next reboot via MoveFileEx/MOVEFILE_DELAY_UNTIL_REBOOT.
//
// tempDir is the directory where the temp file will be created. It must be on
// the same volume as the blocked file (cross-volume rename won't work for
// in-use files).
func removeBlockingExe(blockingErr error, tempDir string) error {
	path, _ := getPathFromError(blockingErr)
	if path == "" {
		return nil
	}

	tmp, err := os.CreateTemp(tempDir, ".elastic-agent-rm-*.exe")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %q: %w", tempDir, err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()

	// os.Rename uses MoveFileEx(MOVEFILE_REPLACE_EXISTING) under the hood.
	if err := os.Rename(path, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename %q to %q: %w", path, tmpPath, err)
	}

	// Schedule the temp file for deletion on next reboot.
	tmpPathPtr, err := windows.UTF16PtrFromString(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to convert temp path: %w", err)
	}
	if err := windows.MoveFileEx(tmpPathPtr, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		// Non-fatal: the file is already out of the way, it just won't be
		// auto-cleaned. Log-worthy but not worth failing the uninstall.
		return fmt.Errorf("failed to schedule %q for deletion on reboot: %w", tmpPath, err)
	}

	return nil
}

// tempDirOnSameVolume returns os.TempDir() if it is on the same volume as
// path, otherwise falls back to the parent of path. Rename/move of an in-use
// file only works within the same volume.
func tempDirOnSameVolume(path string) string {
	sysTemp := os.TempDir()
	pathVol := filepath.VolumeName(path)
	tempVol := filepath.VolumeName(sysTemp)
	if strings.EqualFold(pathVol, tempVol) {
		return sysTemp
	}
	return filepath.Dir(path)
}

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
