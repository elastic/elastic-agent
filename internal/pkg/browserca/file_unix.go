// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package browserca

import (
	"fmt"
	"os"
	"syscall"
)

func openCAFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// Chown the opened inode, rejecting symlinks and hard-linked database files.
// Root confines traversal; descriptor checks avoid a Stat/Lchown substitution race.
func chownDatabasePath(root *os.Root, path string, o *owner, directory bool) error {
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if directory {
		if !info.IsDir() {
			return fmt.Errorf("database path %s is not a directory", path)
		}
	} else if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return fmt.Errorf("database path %s must be a regular file with one link", path)
	}
	return f.Chown(int(o.uid), int(o.gid))
}
