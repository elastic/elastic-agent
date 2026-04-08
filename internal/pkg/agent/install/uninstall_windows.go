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
	"time"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent-libs/logp"
)

// leftoverPrefix is used to rename the install directory during uninstall when
// a running executable prevents deletion. Sibling directories with this prefix
// are cleaned up on the next install.
const leftoverPrefix = ".elastic-agent-leftover"

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

// scheduleDeleteOnReboot renames the entire rootPath directory to a sibling
// directory with a recognizable prefix, then schedules it for deletion on the
// next reboot via MoveFileEx/MOVEFILE_DELAY_UNTIL_REBOOT. Renaming the whole
// directory (rather than moving the exe out of it) avoids triggering EDR
// software that monitors cross-directory file moves. On the next install, any
// leftover sibling directories matching the prefix are cleaned up by
// cleanupLeftoverRenames.
func scheduleDeleteOnReboot(log *logp.Logger, _ error, rootPath string) error {
	parent := filepath.Dir(rootPath)
	renamed := filepath.Join(parent, fmt.Sprintf("%s-%d", leftoverPrefix, time.Now().UnixNano()))

	if err := os.Rename(rootPath, renamed); err != nil {
		return fmt.Errorf("failed to rename %q to %q: %w", rootPath, renamed, err)
	}
	log.Infof("Renamed install directory %q to %q", rootPath, renamed)

	// Schedule all remaining files and directories for deletion on the next
	// reboot. PendingFileRenameOperations entries are processed in order, so
	// scheduling files first and directories bottom-up ensures each directory
	// is empty by the time the Session Manager tries to remove it.
	//
	// By this point os.RemoveAll has already deleted everything it could, so
	// the tree will only contain the running executable and its ancestor
	// directories — a very short walk.
	var dirs []string
	_ = filepath.WalkDir(renamed, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}
		if d.IsDir() {
			dirs = append(dirs, path)
			return nil
		}
		if err := markDeleteOnReboot(path); err != nil {
			log.Warnf("Failed to schedule %q for deletion on reboot: %v. You may need to delete it manually.", path, err)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := markDeleteOnReboot(dirs[i]); err != nil {
			log.Warnf("Failed to schedule directory %q for deletion on reboot: %v. You may need to delete it manually.", dirs[i], err)
		}
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

// cleanupLeftoverRenames removes any sibling directories left behind by a
// previous uninstall's scheduleDeleteOnReboot (directories matching
// leftoverPrefix in the parent of topPath). By the time a new install runs,
// the old process is gone and these directories can be deleted normally.
func cleanupLeftoverRenames(log *logp.Logger, topPath string) error {
	parent := filepath.Dir(topPath)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return fmt.Errorf("failed to read parent directory %q: %w", parent, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), leftoverPrefix) {
			path := filepath.Join(parent, e.Name())
			if err := os.RemoveAll(path); err != nil {
				log.Warnf("Failed to remove leftover directory %q from a previous uninstall: %v. You may need to delete it manually.", path, err)
			}
		}
	}
	return nil
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
