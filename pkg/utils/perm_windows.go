// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package utils

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// AdministratorSID is the SID for the Administrator user.
	AdministratorSID = "S-1-5-32-544"
	// SystemSID is the SID for the SYSTEM user.
	SystemSID = "S-1-5-18"
	// EveryoneSID is the SID for Everyone.
	EveryoneSID = "S-1-1-0"
	// InteractiveSID is the SID for Interactive users.
	InteractiveSID = "S-1-5-4"
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

// writeMask covers all access-mask bits that allow a file's content or
// metadata to be modified, or the file to be deleted/replaced.
const writeMask = windows.ACCESS_MASK(
	windows.GENERIC_WRITE | windows.GENERIC_ALL |
		windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
		windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER,
)

// HasStrictExecPerms ensures that no untrusted SID has write access to the file
// at path. SYSTEM, Administrators, the file owner, and the user running Elastic
// Agent may have any access; all other SIDs must not hold write-capable bits.
func HasStrictExecPerms(path string) error {
	currentOwner, err := CurrentFileOwner()
	if err != nil {
		return fmt.Errorf("failed to get current process owner: %w", err)
	}
	currentUserSID, err := windows.StringToSid(currentOwner.UID)
	if err != nil {
		return fmt.Errorf("failed to parse current process user SID: %w", err)
	}

	return hasStrictExecPerms(path, currentUserSID)
}

func hasStrictExecPerms(path string, currentUserSID *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to get security descriptor for %s: %w", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("failed to get DACL for %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("file %s has a null DACL (fully permissive)", path)
	}

	systemSID, err := windows.StringToSid(SystemSID)
	if err != nil {
		return fmt.Errorf("failed to parse SYSTEM SID: %w", err)
	}
	adminsSID, err := windows.StringToSid(AdministratorSID)
	if err != nil {
		return fmt.Errorf("failed to parse Administrators SID: %w", err)
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("failed to get owner SID for %s: %w", path, err)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("failed to read ACE %d for %s: %w", i, path, err)
		}

		// ACCESS_DENIED_ACEs restrict access and are safe to skip.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))

		// The current process user already controls this Agent process, so
		// trusting it does not permit binary tampering by another account. This
		// also supports Windows tokens whose default file owner differs from the
		// token user, such as a non-elevated member of Administrators.
		if isTrustedExecWriter(sid, systemSID, adminsSID, ownerSID, currentUserSID) {
			continue
		}

		if ace.Mask&writeMask != 0 {
			return fmt.Errorf("non-privileged SID %s has write access to %s", sid.String(), path)
		}
	}

	// Keep sd alive through the loop so that dacl/ace/sid interior pointers
	// remain valid even if a future x/sys version backs the SD with Windows-heap
	// memory subject to a GC finalizer.
	runtime.KeepAlive(sd)
	return nil
}

func isTrustedExecWriter(sid, systemSID, adminsSID, ownerSID, currentUserSID *windows.SID) bool {
	return sid.Equals(systemSID) ||
		sid.Equals(adminsSID) ||
		(ownerSID != nil && sid.Equals(ownerSID)) ||
		sid.Equals(currentUserSID)
}

// HasStrictExecPermsAndOwnership ensures that the path is executable by the
// owner and that the ACLs do not grant write access to non-privileged accounts.
// The uid parameter is unused on Windows; ownership is determined from the
// file's security descriptor.
func HasStrictExecPermsAndOwnership(path string, _ int) error {
	return HasStrictExecPerms(path)
}
