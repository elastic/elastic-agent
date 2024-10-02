// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package chmod

import (
	"io/fs"

	"golang.org/x/sys/windows"
)

func Chmod(name string, fileMode fs.FileMode) error {
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
	entries := []windows.EXPLICIT_ACCESS{
		grantSid(((mode&0700)<<23)|((mode&0200)<<9), creatorOwnerSID),
		grantSid(((mode&0070)<<26)|((mode&0020)<<12), creatorGroupSID),
		grantSid(((mode&0007)<<29)|((mode&0002)<<15), everyoneSID),
	}

	var oldAcl windows.ACL
	acl, err := windows.ACLFromEntries(
		entries,
		&oldAcl,
	)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		name,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func grantSid(accessPermissions uint32, sid *windows.SID) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(accessPermissions),
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
