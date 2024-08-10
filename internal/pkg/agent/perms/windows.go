// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package perms

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only SYSTEM and Administrators have access to the files in the install path
func FixPermissions(topPath string, opts ...OptFunc) error {
	o, err := newOpts(opts...)
	if err != nil {
		return err
	}

	// SYSTEM and Administrators always get permissions
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	systemSID, err := windows.StringToSid(utils.SystemSID)
	if err != nil {
		return fmt.Errorf("failed to get SYSTEM SID: %w", err)
	}
	administratorsSID, err := windows.StringToSid(utils.AdministratorSID)
	if err != nil {
		return fmt.Errorf("failed to get Administrators SID: %w", err)
	}

	// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
	grants := make([]windows.EXPLICIT_ACCESS, 0, 4)
	grants = append(grants, grantSid(0xF10F0000, systemSID))         // full control of all acl's
	grants = append(grants, grantSid(0xF10F0000, administratorsSID)) // full control of all acl's

	// user gets grant based on the mask
	userSID := administratorsSID // defaults to owned by Administrators
	if o.mask&0700 != 0 && o.ownership.UID != "" {
		userSID, err = windows.StringToSid(o.ownership.UID)
		if err != nil {
			return fmt.Errorf("failed to get user %s: %w", o.ownership.UID, err)
		}
		grants = append(grants, grantSid(uint32(((o.mask&0700)<<23)|((o.mask&0200)<<9)), userSID))
	}

	// group gets grant based on the mask
	groupSID := administratorsSID // defaults to owned by Administrators
	if o.mask&0070 != 0 && o.ownership.GID != "" {
		groupSID, err = windows.StringToSid(o.ownership.GID)
		if err != nil {
			return fmt.Errorf("failed to get group %s: %w", o.ownership.GID, err)
		}
		grants = append(grants, grantSid(uint32(((o.mask&0070)<<26)|((o.mask&0020)<<12)), groupSID))
	}

	// everyone gets grant based on the mask
	if o.mask&0007 != 0 {
		everyoneSID, err := windows.StringToSid(utils.EveryoneSID)
		if err != nil {
			return fmt.Errorf("failed to get Everyone SID: %w", err)
		}
		grants = append(grants, grantSid(uint32(((o.mask&0007)<<29)|((o.mask&0002)<<15)), everyoneSID))
	}

	// ownership can only be change to another user when running as Administrator
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("failed to determine Administrator: %w", err)
	}
	if isAdmin {
		// call to `takeOwnership` which sets the ownership information requires the current process
		// token to have the 'SeRestorePrivilege' or it's unable to adjust the ownership
		return winio.RunWithPrivileges([]string{winio.SeRestorePrivilege}, func() error {
			return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
				if err == nil {
					// first level doesn't inherit
					inherit := true
					if topPath == name {
						inherit = false
					}

					err = apply(name, inherit, grants...)
					if err != nil {
						return err
					}
					if userSID != nil && groupSID != nil {
						err = takeOwnership(name, userSID, groupSID)
					}
				} else if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			})
		})
	}

	// ownership cannot be changed, this will keep the ownership as it currently is but apply the ACL's
	return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// first level doesn't inherit
			inherit := true
			if topPath == name {
				inherit = false
			}
			return apply(name, inherit, grants...)
		} else if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

func takeOwnership(name string, owner *windows.SID, group *windows.SID) error {
	return windows.SetNamedSecurityInfo(
		name,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
		owner,
		group,
		nil,
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

func apply(name string, inherit bool, entries ...windows.EXPLICIT_ACCESS) error {
	acl, err := windows.ACLFromEntries(
		entries,
		nil,
	)
	if err != nil {
		return err
	}
	var secInfo windows.SECURITY_INFORMATION
	if !inherit {
		secInfo = windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(
		name,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|secInfo,
		nil,
		nil,
		acl,
		nil,
	)
}
