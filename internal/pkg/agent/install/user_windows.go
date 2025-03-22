// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package install

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"syscall"
	"unsafe"

	"github.com/winlabs/gowin32"
	"golang.org/x/sys/windows"
)

const (
	// Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
	passwordMinLength = 32 // Minimum length for better security
	passwordMaxLength = 64 // Upper limit to avoid policy issues
	// Character pools - ensuring a mix of character categories
	passwordCharsLower   = "abcdefghijklmnopqrstuvwxyz"
	passwordCharsUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	passwordCharsDigits  = "1234567890"
	passwordCharsSpecial = "'-!\"#$%&()*,./:;?@[]^_`{|}~+<=>" //nolint:gosec // G101: False positive on Potential hardcoded credentials
	// Combined pool for general randomization
	passwordAllChars = passwordCharsLower + passwordCharsUpper + passwordCharsDigits + passwordCharsSpecial
)

var (
	modnetapi32 = syscall.NewLazyDLL("netapi32.dll")
	// procNetLocalGroupAdd (https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupadd)
	//   If the function succeeds, the function returns zero (NERR_Success).
	//   If the function fails, the return value is non-zero.
	//   Doesn't set last error.
	procNetLocalGroupAdd = modnetapi32.NewProc("NetLocalGroupAdd")
	// procNetLocalGroupAddMembers (https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers)
	//   If the function succeeds, the function returns zero (NERR_Success).
	//   If the function fails, the return value is non-zero.
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
	// procNetUserAdd (https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd)
	//   If the function succeeds, the function returns zero (NERR_Success).
	//   If the function fails, the return value is non-zero.
	//   Doesn't set last error.
	procNetUserAdd = modnetapi32.NewProc("NetUserAdd")
	// procNetUserSetInfo (https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusersetinfo)
	//   If the function succeeds, the function returns zero (NERR_Success).
	//   If the function fails, the return value is non-zero.
	//   Doesn't set last error.
	procNetUserSetInfo = modnetapi32.NewProc("NetUserSetInfo")
)

const (
	// USER_PRIV_USER is standard user permissions.
	USER_PRIV_USER = 1

	// USER_UF_SCRIPT logon script executed. (always required to be set)
	USER_UF_SCRIPT             = 1
	USER_UF_NORMAL_ACCOUNT     = 512
	USER_UF_DONT_EXPIRE_PASSWD = 65536

	accountRightCreateSymbolicLink gowin32.AccountRightName = "SeCreateSymbolicLinkPrivilege"
)

// FindGID returns the group's GID on the machine.
func FindGID(name string) (string, error) {
	sid, _, t, err := windows.LookupSID("", name)
	if err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			// no account exists with that name
			return "", ErrGroupNotFound
		}
		return "", fmt.Errorf("failed to lookup SID for group %s: %w", name, err)
	}
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
		return "", fmt.Errorf("failed to encode group name %s to UTF16: %w", name, err)
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
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to lookup SID for user %s: %w", name, err)
	}
	if t != windows.SidTypeUser && t != windows.SidTypeAlias {
		return "", fmt.Errorf("invalid SID type for user %s; should be user account type, not %d", name, t)
	}
	return sid.String(), nil
}

// CreateUser creates a user on the machine.
//
// User is created without interactive rights, no logon rights, and only service rights.
func CreateUser(name string, _ string) (string, error) {
	var parmErr uint32
	password, err := RandomPassword()
	if err != nil {
		return "", fmt.Errorf("failed to generate random password: %w", err)
	}
	info := USER_INFO_1{
		Usri1_priv:  USER_PRIV_USER,
		Usri1_flags: USER_UF_SCRIPT | USER_UF_NORMAL_ACCOUNT | USER_UF_DONT_EXPIRE_PASSWD,
	}
	info.Usri1_name, err = syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", fmt.Errorf("failed to encode username %s to UTF16: %w", name, err)
	}
	info.Usri1_password, err = syscall.UTF16PtrFromString(password)
	if err != nil {
		return "", fmt.Errorf("failed to encode password to UTF16: %w", err)
	}
	ret, _, _ := procNetUserAdd.Call(
		uintptr(0),
		uintptr(uint32(1)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if ret != 0 {
		return "", fmt.Errorf("call to NetUserAdd failed: status=%d error=%d", ret, parmErr)
	}

	return FindUID(name)
}

func EnsureRights(name string) error {
	// adjust the local security policy to ensure that the created user is scoped to a service only
	sid, _, _, err := gowin32.GetLocalAccountByName(name)
	if err != nil {
		return fmt.Errorf("failed to get SID for %s: %w", name, err)
	}
	sp, err := gowin32.OpenLocalSecurityPolicy()
	if err != nil {
		return fmt.Errorf("failed to open local security policy: %w", err)
	}
	defer sp.Close()
	err = sp.AddAccountRight(sid, gowin32.AccountRightDenyInteractiveLogon)
	if err != nil {
		return fmt.Errorf("failed to set deny interactive logon: %w", err)
	}
	err = sp.AddAccountRight(sid, gowin32.AccountRightDenyNetworkLogon)
	if err != nil {
		return fmt.Errorf("failed to set deny network logon: %w", err)
	}
	err = sp.AddAccountRight(sid, gowin32.AccountRightDenyRemoteInteractiveLogon)
	if err != nil {
		return fmt.Errorf("failed to set deny remote interactive logon: %w", err)
	}
	err = sp.AddAccountRight(sid, gowin32.AccountRightServiceLogon)
	if err != nil {
		return fmt.Errorf("failed to set service logon: %w", err)
	}
	err = sp.AddAccountRight(sid, accountRightCreateSymbolicLink)
	if err != nil {
		return fmt.Errorf("failed to add right to create symbolic link: %w", err)
	}

	return nil
}

// AddUserToGroup adds a user to a group.
func AddUserToGroup(username string, groupName string) error {
	userSid, _, t, err := windows.LookupSID("", username)
	if err != nil {
		return fmt.Errorf("failed to lookup SID for user %s: %w", username, err)
	}
	if t != windows.SidTypeUser && t != windows.SidTypeAlias {
		return fmt.Errorf("invalid SID type for user %s; should be user account type, not %d", username, t)
	}
	groupNamePtr, err := syscall.UTF16PtrFromString(groupName)
	if err != nil {
		return fmt.Errorf("failed to encode group name %s to UTF16: %w", groupName, err)
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
		uintptr(uint32(len(entries))), //nolint:gosec // G115 max 1
	)
	if ret != 0 {
		return fmt.Errorf("call to NetLocalGroupAddMembers failed: status=%d", ret)
	}
	return nil
}

// SetUserPassword sets the password for a user.
func SetUserPassword(name string, password string) error {
	var parmErr uint32
	var err error
	var info USER_INFO_1003

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("failed to encode username %s to UTF16: %w", name, err)
	}
	info.Usri1003_password, err = syscall.UTF16PtrFromString(password)
	if err != nil {
		return fmt.Errorf("failed to encode password to UTF16: %w", err)
	}
	ret, _, _ := procNetUserSetInfo.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(uint32(1003)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Pointer(&parmErr)),
	)
	if ret != 0 {
		return fmt.Errorf("call to NetUserSetInfo failed: status=%d error=%d", ret, parmErr)
	}
	return nil
}

// RandomPassword generates a secure password that meets Windows policy requirements.
func RandomPassword() (string, error) {
	// Generate a random length within the allowed range
	length, err := rand.Int(rand.Reader, big.NewInt(passwordMaxLength-passwordMinLength+1))
	if err != nil {
		return "", fmt.Errorf("failed to generate random length: %w", err)
	}
	passwordLength := int(length.Int64()) + passwordMinLength
	password := make([]rune, passwordLength)

	// Ensure Windows password constraints are met by guaranteeing at least one character from each category
	filledPositions := make(map[int]any)
	for _, chars := range []string{passwordCharsUpper, passwordCharsLower, passwordCharsDigits, passwordCharsSpecial} {
		// Generate a random position for the character
		var position int
		for {
			posBigInt, err := rand.Int(rand.Reader, big.NewInt(int64(passwordLength)))
			if err != nil {
				return "", fmt.Errorf("failed to generate random position: %w", err)
			}
			position = int(posBigInt.Int64())
			if _, filled := filledPositions[position]; filled {
				// Position already has a missing character, generate a new one
				continue
			}
			break
		}
		// Generate a random character from the given characters
		char, err := randomChar(chars)
		if err != nil {
			// err information is added by randomChar
			return "", err
		}
		// Insert the character into the password
		password[position] = char
		filledPositions[position] = nil
	}

	// Fill the remaining positions with random characters
	for i := 0; i < passwordLength; {
		// Check if the current position has already been filled
		if _, filled := filledPositions[i]; filled {
			// Position already has a character
			i++
			continue
		}
		// Generate a random character from the combined pool of characters
		char, err := randomChar(passwordAllChars)
		if err != nil {
			// err information is added by randomChar
			return "", err
		}
		// Ensure no consecutive duplicate characters to the left
		if i > 0 && password[i-1] == char {
			continue
		}
		// Ensure no consecutive duplicate characters to the right
		if i+1 < passwordLength && password[i+1] == char {
			continue
		}
		// Insert the character into the password
		password[i] = char
		i++
	}

	return string(password), nil
}

// randomChar selects a random character from a given string.
func randomChar(charset string) (rune, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random character: %w", err)
	}
	return rune(charset[n.Int64()]), nil
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

// USER_INFO_1003 structure contains a user password.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1003
type USER_INFO_1003 struct {
	Usri1003_password *uint16
}

// LOCALGROUP_MEMBERS_INFO_0 structure contains the security identifier (SID) associated with a local group member.
// https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-localgroup_members_info_0
type LOCALGROUP_MEMBERS_INFO_0 struct {
	Lgrmi0_sid *windows.SID
}
