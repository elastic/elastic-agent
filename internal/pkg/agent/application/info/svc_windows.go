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
	return false
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

func nativeArchitecture() string {
	var processMachine, nativeMachine uint16
	// the pseudo handle doesn't need to be closed
	var currentProcessHandle = windows.CurrentProcess()

	err := windows.IsWow64Process2(currentProcessHandle, &processMachine, &nativeMachine)
	if err != nil {
		// unknown native architecture
		return ""
	}

	// https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
	const (
		IMAGE_FILE_MACHINE_AMD64 = 0x8664
		IMAGE_FILE_MACHINE_ARM64 = 0xAA64
	)

	var nativeMachineStr string

	switch nativeMachine {
	case IMAGE_FILE_MACHINE_AMD64:
		nativeMachineStr = "amd64"
	case IMAGE_FILE_MACHINE_ARM64:
		nativeMachineStr = "arm64"
	default:
		// other unknown or unsupported by Elastic architectures
		nativeMachineStr = fmt.Sprintf("0x%x", nativeMachine)
	}

	return nativeMachineStr
}
