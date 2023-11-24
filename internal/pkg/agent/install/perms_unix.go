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

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func FixPermissions(topPath string, ownership utils.FileOwner) error {
	return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walk on %q failed: %w", topPath, err)
		}

		// all files should be owned by uid:gid
		// uses `os.Lchown` so the symlink is updated to have the permissions
		if err := os.Lchown(name, ownership.UID, ownership.GID); err != nil {
			return fmt.Errorf("cannot update ownership of %q: %w", topPath, err)
		}

		// remove any world permissions from the file
		if err := os.Chmod(name, info.Mode().Perm()&0770); err != nil {
			return fmt.Errorf("could not update permissions of %q: %w", topPath, err)
		}

		return nil
	})
}
