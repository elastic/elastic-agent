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
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/logp"
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

// scheduleDeleteOnReboot renames the blocked executable to the install root
// with a recognizable prefix, then schedules it for deletion on the next
// reboot via MoveFileEx/MOVEFILE_DELAY_UNTIL_REBOOT. Renaming to the install
// root (rather than to an external temp dir) keeps the file on the same volume
// and within the install tree, avoiding cross-directory move heuristics in EDR
// software. On the next install, leftover files matching the prefix are cleaned
// up by cleanupLeftoverRenames.
func scheduleDeleteOnReboot(log *logp.Logger, blockingErr error, rootPath string) error {
	blockedPath, _ := getPathFromError(blockingErr)
	if blockedPath == "" {
		return fmt.Errorf("could not determine blocked path from error: %w", blockingErr)
	}

	ext := filepath.Ext(blockedPath)
	renamed := filepath.Join(rootPath, fmt.Sprintf("%s-%d%s", leftoverPrefix, time.Now().UnixNano(), ext))

	if err := os.Rename(blockedPath, renamed); err != nil {
		return fmt.Errorf("failed to rename %q to %q: %w", blockedPath, renamed, err)
	}
	log.Infof("Renamed blocked executable %q to %q", blockedPath, renamed)

	if err := markDeleteOnReboot(renamed); err != nil {
		log.Warnf("Failed to schedule %q for deletion on reboot: %v. You may need to delete it manually.", renamed, err)
	} else {
		log.Infof("Scheduled %q for deletion on reboot", renamed)
	}

	return nil
}

// markDeleteOnReboot schedules a file or directory for deletion on the next
// Windows reboot. This only writes a registry entry
// (PendingFileRenameOperations) and does not touch the file itself.
func markDeleteOnReboot(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
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
