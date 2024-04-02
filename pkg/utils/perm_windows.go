// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package utils

import (
	"os/user"
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
//
// Note: Very unlikely for this to panic if this function is unable to get the current
// user. Not being able to get the current user, is a critical problem and nothing
// can continue so a panic is appropriate.
func CurrentFileOwner() FileOwner {
	u, err := user.Current()
	if err != nil {
		// should not fail; if it does then there is a big problem
		panic(err)
	}
	return FileOwner{
		UID: u.Uid,
		GID: u.Gid,
	}
}

// HasStrictExecPerms ensures that the path is executable by the owner and that the owner of the file
// is the same as the UID or root.
func HasStrictExecPerms(path string, uid int) error {
	// TODO: Need to add check on Windows to ensure that the ACL are correct for the binary before execution.
	return nil
}
