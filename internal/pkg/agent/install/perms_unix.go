// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// fixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func fixPermissions(topPath string) error {
	return recursiveRootPermissions(topPath)
}

func recursiveRootPermissions(path string) error {
	return filepath.Walk(path, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// all files should be owned by root:root
			err = os.Chown(name, 0, 0)
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
