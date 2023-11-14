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

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func FixPermissions(topPath string, ownership utils.FileOwner) error {
	return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// all files should be owned by uid:gid
			// uses `os.Lchown` so the symlink is updated to have the permissions
			err = os.Lchown(name, ownership.UID, ownership.GID)
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
