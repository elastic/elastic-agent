// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

// fixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func fixPermissions(topPath string, uidStr string, gidStr string) error {
	var err error

	uid := os.Getuid()
	gid := os.Getgid()
	if uidStr != "" {
		uid, err = strconv.Atoi(uidStr)
		if err != nil {
			return fmt.Errorf("failed to convert uid(%s) to int: %w", uidStr, err)
		}
	}
	if gidStr != "" {
		gid, err = strconv.Atoi(gidStr)
		if err != nil {
			return fmt.Errorf("failed to convert gid(%s) to int: %w", gidStr, err)
		}
	}

	return recursiveRootPermissions(topPath, uid, gid)
}

func recursiveRootPermissions(path string, uid int, gid int) error {
	return filepath.Walk(path, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// all files should be owned by uid:gid
			// uses `os.Lchown` so the symlink is updated to have the permissions
			err = os.Lchown(name, uid, gid)
			if err != nil {
				return err
			}
			// remove any world permissions from the file
			err = os.Chmod(name, info.Mode().Perm()&0770)
		} else if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}
