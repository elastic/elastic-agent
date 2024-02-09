// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modnetapi32                 = syscall.NewLazyDLL("netapi32.dll")
	procNetLocalGroupAdd        = modnetapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
	procNetUserAdd              = modnetapi32.NewProc("NetUserAdd")
)

const (
	// USER_PRIV_USER is standard user permissions.
	USER_PRIV_USER = 1

	// USER_UF_SCRIPT logon script executed. (always required to be set)
	USER_UF_SCRIPT             = 1
	USER_UF_NORMAL_ACCOUNT     = 512
	USER_UF_DONT_EXPIRE_PASSWD = 65536
)

// FindGID returns the group's GID on the machine.
func FindGID(name string) (string, error) {
	sid, _, t, err := windows.LookupSID("", name)
	if err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			// no account exists with that name
			return "", nil
		}
		return "", fmt.Errorf("failed to lookup SID for group %s: %w", name, err)
	}
	defer windows.FreeSid(sid)
	if t != windows.SidTypeGroup && t != windows.SidTypeWellKnownGroup && t != windows.SidTypeAlias {
		return "", fmt.Errorf("invalid SID type for group %s; should be group account type, not %d", name, t)
	}
	return sid.String(), nil
}

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (string, error) {
	var parmErr uint32
	var err error
	var info LOCALGROUP_INFO_0
	info.Lgrpi0_name, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", fmt.Errorf("failed to encode group name %s to UTF16: %s", name, err)
	}
	ret, _, _ := procNetLocalGroupAdd.Call(
		uintptr(0),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if ret != 0 {
		return "", fmt.Errorf("call to NetLocalGroupAdd failed: status=%d error=%d", ret, parmErr)
	}
	return FindGID(name)
}

// FindUID returns the user's UID on the machine.
func FindUID(name string) (string, error) {
	sid, _, t, err := windows.LookupSID("", name)
	if err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			// no account exists with that name
			return "", nil
		}
		return "", fmt.Errorf("failed to lookup SID for user %s: %w", name, err)
	}
	defer windows.FreeSid(sid)
	if t != windows.SidTypeUser && t != windows.SidTypeAlias {
		return "", fmt.Errorf("invalid SID type for user %s; should be user account type, not %d", name, t)
	}
	return sid.String(), nil
}

// CreateUser creates a user on the machine.
func CreateUser(name string, _ string) (string, error) {
	var parmErr uint32
	var err error
	info := USER_INFO_1{
		Usri1_priv:  USER_PRIV_USER,
		Usri1_flags: USER_UF_SCRIPT | USER_UF_NORMAL_ACCOUNT | USER_UF_DONT_EXPIRE_PASSWD,
	}
	info.Usri1_name, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", fmt.Errorf("failed to encode username %s to UTF16: %s", name, err)
	}
	//uInfo.Usri1_password, err = syscall.UTF16PtrFromString(opts.Password)
	//if err != nil {
	//	return false, fmt.Errorf("Unable to encode password to UTF16: %s", err)
	//}
	ret, _, _ := procNetUserAdd.Call(
		uintptr(0),
		uintptr(uint32(1)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if ret != 0 {
		return "", fmt.Errorf("call to NetUserAdd failed: status=%d error=%d", ret, parmErr)
	}

	// must be manually added to the Users group when its created
	err = AddUserToGroup(name, "Users")
	if err != nil {
		// error information from AddUserToGroup is enough
		return "", err
	}
	return FindUID(name)
}

// AddUserToGroup adds a user to a group.
func AddUserToGroup(username string, groupName string) error {
	userSid, _, t, err := windows.LookupSID("", username)
	if err != nil {
		return fmt.Errorf("failed to lookup SID for user %s: %w", username, err)
	}
	defer windows.FreeSid(userSid)
	if t != windows.SidTypeUser && t != windows.SidTypeAlias {
		return fmt.Errorf("invalid SID type for user %s; should be user account type, not %d", username, t)
	}
	groupNamePtr, err := syscall.UTF16PtrFromString(groupName)
	if err != nil {
		return fmt.Errorf("failed to encode group name %s to UTF16: %s", groupName, err)
	}
	entries := make([]LOCALGROUP_MEMBERS_INFO_0, 1)
	entries[0] = LOCALGROUP_MEMBERS_INFO_0{
		Lgrmi0_sid: userSid,
	}
	ret, _, _ := procNetLocalGroupAddMembers.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(groupNamePtr)),
		uintptr(uint32(0)),
		uintptr(unsafe.Pointer(&entries[0])),
		uintptr(uint32(len(entries))),
	)
	if ret != 0 {
		return fmt.Errorf("call to NetLocalGroupAddMembers failed: status=%d", ret)
	}
	return nil
}

// LOCALGROUP_INFO_0 structure contains a local group name.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_info_0
type LOCALGROUP_INFO_0 struct {
	Lgrpi0_name *uint16
}

// USER_INFO_1 structure contains information about a user account, including account name, password data,
// privilege level, and the path to the user's home directory.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1
type USER_INFO_1 struct {
	Usri1_name         *uint16
	Usri1_password     *uint16
	Usri1_password_age uint32
	Usri1_priv         uint32
	Usri1_home_dir     *uint16
	Usri1_comment      *uint16
	Usri1_flags        uint32
	Usri1_script_path  *uint16
}

// LOCALGROUP_MEMBERS_INFO_0 structure contains the security identifier (SID) associated with a local group member.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_0
type LOCALGROUP_MEMBERS_INFO_0 struct {
	Lgrmi0_sid *windows.SID
}
