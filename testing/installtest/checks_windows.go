// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package installtest

import (
	"context"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/agent/install"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
)

const ACCESS_ALLOWED_ACE_TYPE = 0
const ACCESS_DENIED_ACE_TYPE = 1

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetAce = advapi32.NewProc("GetAce")
)

type accessAllowedAce struct {
	AceType    uint8
	AceFlags   uint8
	AceSize    uint16
	AccessMask uint32
	SidStart   uint32
}

func checkPlatform(ctx context.Context, f *atesting.Fixture, topPath string, opts *CheckOpts) error {
	secInfo, err := windows.GetNamedSecurityInfo(topPath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("GetNamedSecurityInfo failed for %s: %w", topPath, err)
	}
	if !secInfo.IsValid() {
		return fmt.Errorf("GetNamedSecurityInfo result is not valid for %s: %w", topPath, err)
	}
	owner, _, err := secInfo.Owner()
	if err != nil {
		return fmt.Errorf("secInfo.Owner() failed for %s: %w", topPath, err)
	}
	sids, err := getAllowedSIDs(secInfo)
	if err != nil {
		return fmt.Errorf("failed to get allowed SID's for %s: %w", topPath, err)
	}
	if !opts.Privileged {
		// Check that the elastic-agent user/group exist.
		uid, err := install.FindUID(install.ElasticUsername)
		if err != nil {
			return fmt.Errorf("failed to find %s user: %w", install.ElasticUsername, err)
		}
		uidSID, err := windows.StringToSid(uid)
		if err != nil {
			return fmt.Errorf("failed to convert string to windows.SID %s: %w", uid, err)
		}
		gid, err := install.FindGID(install.ElasticGroupName)
		if err != nil {
			return fmt.Errorf("failed to find %s group: %w", install.ElasticGroupName, err)
		}
		gidSID, err := windows.StringToSid(gid)
		if err != nil {
			return fmt.Errorf("failed to convert string to windows.SID %s: %w", uid, err)
		}
		if !owner.Equals(uidSID) {
			return fmt.Errorf("%s not owned by %s user", topPath, install.ElasticUsername)
		}
		if !hasSID(sids, uidSID) {
			return fmt.Errorf("path %s should have ACE for %s user", topPath, install.ElasticUsername)
		}
		if !hasSID(sids, gidSID) {
			return fmt.Errorf("path %s should have ACE for %s group", topPath, install.ElasticGroupName)
		}
		// administrators should have access as well
		if !hasWellKnownSID(sids, windows.WinBuiltinAdministratorsSid) {
			return fmt.Errorf("path %s should have ACE for Administrators", topPath)
		}
		// that is 3 unique SID's, it should not have anymore
		if len(sids) > 3 {
			return fmt.Errorf("DACL has more than allowed ACE for %s", topPath)
		}
	} else {
		if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return fmt.Errorf("%s not owned by Administrators", topPath)
		}
		// that is 1 unique SID, it should not have anymore
		if len(sids) > 1 {
			return fmt.Errorf("DACL has more than allowed ACE for %s", topPath)
		}
	}
	return nil
}

func hasSID(sids []*windows.SID, m *windows.SID) bool {
	for _, s := range sids {
		if s.Equals(m) {
			return true
		}
	}
	return false
}

func appendSID(sids []*windows.SID, a *windows.SID) []*windows.SID {
	if hasSID(sids, a) {
		return sids
	}
	return append(sids, a)
}

func hasWellKnownSID(sids []*windows.SID, m windows.WELL_KNOWN_SID_TYPE) bool {
	for _, s := range sids {
		if s.IsWellKnown(m) {
			return true
		}
	}
	return false
}

func getAllowedSIDs(secInfo *windows.SECURITY_DESCRIPTOR) ([]*windows.SID, error) {
	dacl, _, err := secInfo.DACL()
	if err != nil {
		return nil, fmt.Errorf("secInfo.DACL() failed: %w", err)
	}
	if dacl == nil {
		return nil, fmt.Errorf("no DACL set")
	}

	var sids []*windows.SID

	// sadly the ACL information is not exported so reflect is needed to get the aceCount
	// it's always field #3 because it's defined by the Windows API (so no real need to worry about it changing)
	rs := reflect.ValueOf(dacl).Elem()
	aceCount := rs.Field(3).Uint()
	for i := uint64(0); i < aceCount; i++ {
		ace := &accessAllowedAce{}
		ret, _, _ := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ret == 0 {
			return nil, fmt.Errorf("while getting ACE: %w", windows.GetLastError())
		}
		if ace.AceType == ACCESS_DENIED_ACE_TYPE {
			// we never set denied ACE, something is wrong
			return nil, fmt.Errorf("denied ACE found (should not be set)")
		}
		if ace.AceType != ACCESS_ALLOWED_ACE_TYPE {
			// unknown ace type
			return nil, fmt.Errorf("unknown AceType: %d", ace.AceType)
		}
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sids = appendSID(sids, aceSid)
	}
	return sids, nil
}
