// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package acl

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379638.aspx
const (
	TRUSTEE_IS_SID = iota
	TRUSTEE_IS_NAME
	TRUSTEE_BAD_FORM
	TRUSTEE_IS_OBJECTS_AND_SID
	TRUSTEE_IS_OBJECTS_AND_NAME
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379593.aspx
const (
	SE_UNKNOWN_OBJECT_TYPE = iota
	SE_FILE_OBJECT
	SE_SERVICE
	SE_PRINTER
	SE_REGISTRY_KEY
	SE_LMSHARE
	SE_KERNEL_OBJECT
	SE_WINDOW_OBJECT
	SE_DS_OBJECT
	SE_DS_OBJECT_ALL
	SE_PROVIDER_DEFINED_OBJECT
	SE_WMIGUID_OBJECT
	SE_REGISTRY_WOW64_32KEY
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374899.aspx
const (
	NOT_USED_ACCESS = iota
	GRANT_ACCESS
	SET_ACCESS
	DENY_ACCESS
	REVOKE_ACCESS
	SET_AUDIT_SUCCESS
	SET_AUDIT_FAILURE
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
const (
	NO_INHERITANCE                     = 0x0
	SUB_OBJECTS_ONLY_INHERIT           = 0x1
	SUB_CONTAINERS_ONLY_INHERIT        = 0x2
	SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
	INHERIT_NO_PROPAGATE               = 0x4
	INHERIT_ONLY                       = 0x8

	OBJECT_INHERIT_ACE       = 0x1
	CONTAINER_INHERIT_ACE    = 0x2
	NO_PROPAGATE_INHERIT_ACE = 0x4
	INHERIT_ONLY_ACE         = 0x8
)

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379573.aspx
const (
	OWNER_SECURITY_INFORMATION               = 0x00001
	GROUP_SECURITY_INFORMATION               = 0x00002
	DACL_SECURITY_INFORMATION                = 0x00004
	SACL_SECURITY_INFORMATION                = 0x00008
	LABEL_SECURITY_INFORMATION               = 0x00010
	ATTRIBUTE_SECURITY_INFORMATION           = 0x00020
	SCOPE_SECURITY_INFORMATION               = 0x00040
	PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00080
	BACKUP_SECURITY_INFORMATION              = 0x10000

	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
)

var (
	advapi32 = windows.MustLoadDLL("advapi32.dll")
	// procGetNamedSecurityInfoW (https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow)
	//   If the function succeeds, the return value is ERROR_SUCCESS.
	//   If the function fails, the return value is a nonzero error code defined in WinError.h.
	//   Doesn't set last error.
	procGetNamedSecurityInfoW = advapi32.MustFindProc("GetNamedSecurityInfoW")
	// procSetNamedSecurityInfoW (https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
	//   If the function succeeds, the return value is ERROR_SUCCESS.
	//   If the function fails, the return value is a nonzero error code defined in WinError.h.
	//   Doesn't set last error.
	procSetNamedSecurityInfoW = advapi32.MustFindProc("SetNamedSecurityInfoW")
	// procSetEntriesInAclW (https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setentriesinaclw)
	//   If the function succeeds, the return value is ERROR_SUCCESS.
	//   If the function fails, the return value is a nonzero error code defined in WinError.h.
	//   Doesn't set last error.
	procSetEntriesInAclW = advapi32.MustFindProc("SetEntriesInAclW")
)

// Trustee defines the user account, group account, or logon session to which an access control entry (ACE) applies.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379636.aspx
type Trustee struct {
	MultipleTrustee          *Trustee
	MultipleTrusteeOperation int32
	TrusteeForm              int32
	TrusteeType              int32
	Name                     *uint16
}

// ExplicitAccess defines access control information for a specified Trustee.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa446627.aspx
type ExplicitAccess struct {
	AccessPermissions uint32
	AccessMode        int32
	Inheritance       uint32
	Trustee           Trustee
}

// GrantSid creates an ExplicitAccess instance granting permissions to the provided SID.
func GrantSid(accessPermissions uint32, sid *windows.SID) ExplicitAccess {
	return ExplicitAccess{
		AccessPermissions: accessPermissions,
		AccessMode:        GRANT_ACCESS,
		Inheritance:       SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: Trustee{
			TrusteeForm: TRUSTEE_IS_SID,
			Name:        (*uint16)(unsafe.Pointer(sid)),
		},
	}
}

// Chmod changes the permissions of the specified file. Only the nine
// least-significant bytes are used, allowing access by the file's owner, the
// file's group, and everyone else to be explicitly controlled.
func Chmod(name string, fileMode os.FileMode) error {
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	creatorOwnerSID, err := windows.StringToSid("S-1-3-0")
	if err != nil {
		return err
	}
	creatorGroupSID, err := windows.StringToSid("S-1-3-1")
	if err != nil {
		return err
	}
	everyoneSID, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return err
	}

	mode := uint32(fileMode)
	return Apply(
		name,
		true,
		false,
		// For owner permissions:
		// (mode&0700)<<23: Extracts the rwx bits for owner (bits 8-6) and shifts them
		// to bits 31-29 in the Windows ACL
		// (mode&0200)<<9: Extracts the write bit for owner (bit 7) and shifts it
		// to bit 16 in the Windows ACL (for additional write permissions)
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
		GrantSid(((mode&0700)<<23)|((mode&0200)<<9), creatorOwnerSID),
		// For group permissions:
		// (mode&0070)<<26: Extracts the rwx bits for group (bits 5-3) and shifts them
		// to bits 31-29 in the Windows ACL
		// (mode&0020)<<12: Extracts the write bit for group (bit 4) and shifts it
		// to bit 16 in the Windows ACL (for additional write permissions)
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
		GrantSid(((mode&0070)<<26)|((mode&0020)<<12), creatorGroupSID),
		// For other/everyone permissions:
		// (mode&0007)<<29: Extracts the rwx bits for others (bits 2-0) and shifts them
		// to bits 31-29 in the Windows ACL
		// (mode&0002)<<15: Extracts the write bit for others (bit 1) and shifts it
		// to bit 16 in the Windows ACL (for additional write permissions)
		// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
		GrantSid(((mode&0007)<<29)|((mode&0002)<<15), everyoneSID),
	)
}

// TakeOwnership changes the owner and group of the specified file.
func TakeOwnership(name string, owner *windows.SID, group *windows.SID) error {
	return SetNamedSecurityInfo(
		name,
		SE_FILE_OBJECT,
		OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION,
		owner,
		group,
		0,
		0,
	)
}

// SetEntriesInAcl creates a new access control list (ACL) by merging new access
// control or audit control information into an existing ACL structure.
func SetEntriesInAcl(entries []ExplicitAccess, oldAcl windows.Handle, newAcl *windows.Handle) error {
	var entriesPtr unsafe.Pointer
	if len(entries) > 0 {
		entriesPtr = unsafe.Pointer(&entries[0])
	}

	ret, _, _ := procSetEntriesInAclW.Call(
		uintptr(len(entries)),
		uintptr(entriesPtr),
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if ret != 0 {
		return fmt.Errorf("call to SetEntriesInAclW failed: ret=%d", ret)
	}
	return nil
}

// GetNamedSecurityInfo retrieves a copy of the security descriptor for an
// object specified by name.
func GetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group **windows.SID, dacl, sacl, secDesc *windows.Handle) error {
	ret, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(unsafe.Pointer(dacl)),
		uintptr(unsafe.Pointer(sacl)),
		uintptr(unsafe.Pointer(secDesc)),
	)
	if ret != 0 {
		return fmt.Errorf("call to GetNamedSecurityInfoW failed: ret=%d", ret)
	}
	return nil
}

// SetNamedSecurityInfo sets specified security information in the security descriptor of a specified object.
// The caller identifies the object by name.
func SetNamedSecurityInfo(objectName string, objectType int32, secInfo uint32, owner, group *windows.SID, dacl, sacl windows.Handle) error {
	ret, _, _ := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(objectName))),
		uintptr(objectType),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(owner)),
		uintptr(unsafe.Pointer(group)),
		uintptr(dacl),
		uintptr(sacl),
	)
	if ret != 0 {
		return fmt.Errorf("call to SetNamedSecurityInfoW failed: ret=%d", ret)
	}
	return nil
}

// Apply the provided access control entries to a file. If the replace
// parameter is true, existing entries will be overwritten. If the inherit
// parameter is true, the file will inherit ACEs from its parent.
func Apply(name string, replace, inherit bool, entries ...ExplicitAccess) error {
	var oldAcl windows.Handle
	if !replace {
		var secDesc windows.Handle
		if err := GetNamedSecurityInfo(
			name,
			SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION,
			nil,
			nil,
			&oldAcl,
			nil,
			&secDesc,
		); err != nil {
			return err
		}
		// NOTE: according to the GetNamedSecurityInfoW documentation you shouldn't
		//   free windows.LocalFree(oldAcl)
		defer windows.LocalFree(secDesc) //nolint:errcheck // not much we can do
	}
	var acl windows.Handle
	if err := SetEntriesInAcl(
		entries,
		oldAcl,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree(acl) //nolint:errcheck // not much we can do
	var secInfo uint32
	if !inherit {
		secInfo = PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return SetNamedSecurityInfo(
		name,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION|secInfo,
		nil,
		nil,
		acl,
		0,
	)
}
