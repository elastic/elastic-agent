// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package info

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// RunningUnderSupervisor returns true when executing Agent is running under
// the supervisor processes of the OS.
//
// Checks in the following order:
//  1. Has SECURITY_LOCAL_SYSTEM_RID (aka. running as LOCAL SYSTEM)
//  2. Has SECURITY_SERVICE_RID (aka. running as service as non LOCAL SYSTEM user)
func RunningUnderSupervisor() bool {
	localSystem, _ := hasLocalSystemSID()
	if localSystem {
		return true
	}
	isService, _ := hasServiceSID()
	return isService
}

func hasLocalSystemSID() (bool, error) {
	// local system RID is given to processes that are running as a service
	// with local system rights.
	sid, err := allocSid(windows.SECURITY_LOCAL_SYSTEM_RID)
	if err != nil {
		return false, fmt.Errorf("allocate sid error: %w", err)
	}
	defer func() {
		_ = windows.FreeSid(sid)
	}()

	// Internally uses CheckTokenMembership where `windows.Token(0)` represents a NULL
	// token which uses the current process token.
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token membership error: %w", err)
	}

	return member, nil
}

func hasServiceSID() (bool, error) {
	// service RID is given to processes that are running as a service
	// but do not have local system rights.
	sid, err := allocSid(windows.SECURITY_SERVICE_RID)
	if err != nil {
		return false, fmt.Errorf("allocate sid error: %w", err)
	}
	defer func() {
		_ = windows.FreeSid(sid)
	}()

	// Internally uses CheckTokenMembership where `windows.Token(0)` represents a NULL
	// token which uses the current process token.
	// https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token membership error: %w", err)
	}

	return member, nil
}

// allocSID creates a SID from the provided subAuth0.
//
// allocated SID must be freed with `windows.FreeSid`.
func allocSid(subAuth0 uint32) (*windows.SID, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY,
		1, subAuth0, 0, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return nil, err
	}
	return sid, nil
}
