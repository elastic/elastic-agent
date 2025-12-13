// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package utils

import (
	"errors"
	"os"

	"github.com/elastic/elastic-agent-libs/file"
)

// FileOwner is the ownership a file should have.
type FileOwner struct {
	UID int
	GID int
}

// CurrentFileOwner returns the executing UID and GID of the current process.
func CurrentFileOwner() (FileOwner, error) {
	return FileOwner{
		UID: os.Getuid(),
		GID: os.Getgid(),
	}, nil
}

// HasStrictExecPerms ensures that the path is executable by the owner, cannot be written by anyone other than the
// owner of the file and that the owner of the file is the same as the UID or root.
func HasStrictExecPerms(path string) error {
	info, err := file.Stat(path)
	if err != nil {
		return err
	}

	return hasStrictExecPerms(info)
}

// HasStrictExecPermsAndOwnership ensures that the path is executable by the owner and that the owner of the file
// is the same as the UID or root.
func HasStrictExecPermsAndOwnership(path string, uid int) error {
	info, err := file.Stat(path)
	if err != nil {
		return err
	}

	if err := hasStrictExecPerms(info); err != nil {
		return err
	}

	fileUID, err := info.UID()
	if err != nil {
		return err
	}

	if fileUID != 0 && fileUID != uid {
		return errors.New("file owner does not match expected UID or root")
	}

	return nil
}

func hasStrictExecPerms(info file.FileInfo) error {
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
