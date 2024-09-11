// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package utils

import (
	"fmt"
	"syscall"
)

const (
	// AdministratorSID is the SID for the Administrator user.
	AdministratorSID = "S-1-5-32-544"
	// SystemSID is the SID for the SYSTEM user.
	SystemSID = "S-1-5-32-544"
	// EveryoneSID is the SID for Everyone.
	EveryoneSID = "S-1-1-0"
)

// FileOwner is the ownership a file should have.
type FileOwner struct {
	UID string
	GID string
}

// CurrentFileOwner returns the executing UID and GID of the current process.
func CurrentFileOwner() (FileOwner, error) {
	// os/user.Current() is not used here, because it tries to access the users home
	// directory. It is possible during installation that the users home directory
	// is not created yet. See issue https://github.com/elastic/elastic-agent/issues/5019
	// for more information.
	t, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return FileOwner{}, fmt.Errorf("failed to open current process token: %w", err)
	}
	defer func() {
		_ = t.Close()
	}()
	u, err := t.GetTokenUser()
	if err != nil {
		return FileOwner{}, fmt.Errorf("failed to get token user: %w", err)
	}
	pg, err := t.GetTokenPrimaryGroup()
	if err != nil {
		return FileOwner{}, fmt.Errorf("failed to get token primary group: %w", err)
	}
	uid, err := u.User.Sid.String()
	if err != nil {
		return FileOwner{}, fmt.Errorf("failed to convert token user sid to string: %w", err)
	}
	gid, err := pg.PrimaryGroup.String()
	if err != nil {
		return FileOwner{}, fmt.Errorf("failed to convert token primary group sid to string: %w", err)
	}
	return FileOwner{
		UID: uid,
		GID: gid,
	}, nil
}

// HasStrictExecPerms ensures that the path is executable by the owner and that the owner of the file
// is the same as the UID or root.
func HasStrictExecPerms(path string, uid int) error {
	// TODO: Need to add check on Windows to ensure that the ACL are correct for the binary before execution.
	return nil
}
