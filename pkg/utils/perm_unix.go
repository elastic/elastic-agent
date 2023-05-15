// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package utils

import (
	"errors"
	"os"
)

// HasStrictExecPerms ensures that the path is executable by the owner, cannot be written by anyone other than the
// owner of the file and that the owner of the file is the same as the UID or root.
func HasStrictExecPerms(path string, uid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("is a directory")
	}
	if info.Mode()&0022 != 0 {
		return errors.New("cannot be writeable by group or other")
	}
	if info.Mode()&0100 == 0 {
		return errors.New("not executable by owner")
	}
	return nil
}
