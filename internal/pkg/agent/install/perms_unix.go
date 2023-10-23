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
)

// fixPermissions fixes the permissions so only root:root is the owner and no world read-able permissions
func fixPermissions(topPath string) error {
	return recursiveRootPermissions(topPath)
}

func recursiveRootPermissions(root string) error {
	return filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("walk on %q failed: %w", path, err)
		}

		// all files should be owned by root:root
		err = os.Chown(path, 0, 0)
		if err != nil {
			return fmt.Errorf("could not fix ownership of %q: %w", path, err)
		}
		// remove any world permissions from the file
		err = os.Chmod(path, info.Mode().Perm()&0770)
		if err != nil {
			return fmt.Errorf("could not fix permissions of %q: %w", path, err)
		}

		return nil
	})
}
