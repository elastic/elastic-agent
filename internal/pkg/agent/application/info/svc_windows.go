// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package info

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const (
	ML_SYSTEM_RID = 0x4000
)

// RunningUnderSupervisor returns true when executing Agent is running under
// the supervisor processes of the OS.
func RunningUnderSupervisor() bool {
	serviceSid, err := allocSid(ML_SYSTEM_RID)
	if err != nil {
		return false
	}
	defer windows.FreeSid(serviceSid)

	t, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer t.Close()

	gs, err := t.GetTokenGroups()
	if err != nil {
		return false
	}

	for _, g := range gs.AllGroups() {
		if windows.EqualSid(g.Sid, serviceSid) {
			return true
		}
	}

	// fallback check if process has service token
	isService, _ := hasServiceToken()
	return isService
}

func allocSid(subAuth0 uint32) (*windows.SID, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(&windows.SECURITY_MANDATORY_LABEL_AUTHORITY,
		1, subAuth0, 0, 0, 0, 0, 0, 0, 0, &sid)
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// hasServiceToken returns true process token has the service token added.
//
// When spawned by the process manager as a specific user the process gets this token.
func hasServiceToken() (bool, error) {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		1,
		windows.SECURITY_SERVICE_RID,
		0, 0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false, fmt.Errorf("allocate sid error: %w", err)
	}
	defer func() {
		_ = windows.FreeSid(sid)
	}()

	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		return false, fmt.Errorf("token membership error: %w", err)
	}

	return member, nil
}
