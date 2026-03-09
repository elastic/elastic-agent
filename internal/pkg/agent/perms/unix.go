// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package perms

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"strings"
	"runtime"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func FixPermissions(topPath string, opts ...OptFunc) error {
	o, err := newOpts(opts...)
	if err != nil {
		return err
	}
	return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walk on %q failed: %w", topPath, err)
		}

		// all files should be owned by uid:gid
		// uses `os.Lchown` so the symlink is updated to have the permissions
		if err := os.Lchown(name, o.ownership.UID, o.ownership.GID); err != nil {
			if !errors.Is(err, syscall.EPERM) {
				// fail right away if the error is not a permission error
				return fmt.Errorf("cannot update ownership of %q: %w", topPath, err)
			}

			if isOSQueryApp(name) {
				// ignore the error if the file is osquery.app
				return nil
			}

			// check desired owner is same as current file owner, if so, ignore the error as it is likely a permission issue with the user running the agent and not an issue with the file ownership
			if same, sErr := isSameUser(info, o.ownership); sErr != nil || !same {
				return fmt.Errorf("cannot update ownership of %q: %w", topPath, err)
			}
		}

		// remove any world permissions from the file
		if err := os.Chmod(name, info.Mode().Perm()&o.mask); err != nil {
			if !errors.Is(err, syscall.EPERM) {
				// fail right away if the error is not a permission error
				return fmt.Errorf("cannot update ownership of %q: %w", topPath, err)
			}

			if isOSQueryApp(name) {
				// ignore the error if the file is osquery.app
				return nil
			}

			// check desired mode is same as current file mode, if so, ignore the error as it is likely a permission issue with the user running the agent and not an issue with the file permissions
			if !maskIsStripped(info, o.mask) {
				return fmt.Errorf("cannot update permissions of %q: %w", topPath, err)
			}
		}

		return nil
	})
}

func isSameUser(info fs.FileInfo, ownership utils.FileOwner) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false, fmt.Errorf("failed to get stat_t for %q", info.Name())
	}

	return stat.Uid == uint32(ownership.UID) && stat.Gid == uint32(ownership.GID), nil //nolint:gosec // G115 Conversion from int to uint32 is safe here.
}

func maskIsStripped(info fs.FileInfo, mask os.FileMode) bool {
	return info.Mode().Perm()&mask == 0
}

func isOSQueryApp(path string) bool {
	// on mac check if part of the path is "osquery.app"
	if runtime.GOOS == "darwin" {
		return strings.Contains(path, "osquery.app")
	}
	return false
}