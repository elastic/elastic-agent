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
func fixPermissions(topPath string, uid string, gid string) error {
	var uidInt int
	var gidInt int
	var err error

	if uid == "" {
		uidInt = os.Geteuid()
	} else {
		uidInt, err = strconv.Atoi(uid)
		if err != nil {
			return fmt.Errorf("failed to convert uid(%s) to int: %w", uid, err)
		}
	}

	if gid == "" {
		gidInt = os.Getegid()
	} else {
		gidInt, err = strconv.Atoi(gid)
		if err != nil {
			return fmt.Errorf("failed to convert gid(%s) to int: %w", gid, err)
		}
	}

	return recursiveRootPermissions(topPath, uidInt, gidInt)
}

func recursiveRootPermissions(path string, uid int, gid int) error {
	return filepath.Walk(path, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// all files should be owned by root:root
			err = os.Chown(name, uid, gid)
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
