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
	"github.com/hectane/go-acl"
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only SYSTEM and Administrators have access to the files in the install path
func FixPermissions(topPath string, opts ...OptFunc) error {
	o := newOpts(opts...)

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
	grants := make([]api.ExplicitAccess, 0, 4)
	grants = append(grants, acl.GrantSid(0xF10F0000, systemSID))         // full control of all acl's
	grants = append(grants, acl.GrantSid(0xF10F0000, administratorsSID)) // full control of all acl's

	// user gets full control of the acl's when set
	var userSID *windows.SID
	if o.ownership.UID != "" {
		userSID, err = windows.StringToSid(o.ownership.UID)
		if err != nil {
			return fmt.Errorf("failed to get user %s: %w", o.ownership.UID, err)
		}
		grants = append(grants, acl.GrantSid(uint32(((o.mask&0700)<<23)|((o.mask&0200)<<9)), userSID))
	}

	// group only gets READ_CONTROL rights
	var groupSID *windows.SID
	if o.ownership.GID != "" {
		groupSID, err = windows.StringToSid(o.ownership.GID)
		if err != nil {
			return fmt.Errorf("failed to get group %s: %w", o.ownership.GID, err)
		}
		grants = append(grants, acl.GrantSid(uint32(((o.mask&0070)<<26)|((o.mask&0020)<<12)), groupSID))
	}

	// everyone grant SID
	everyoneSID, err := windows.StringToSid(utils.EveryoneSID)
	if err != nil {
		return fmt.Errorf("failed to get Everyone SID: %w", err)
	}
	grants = append(grants, acl.GrantSid(uint32(((o.mask&0007)<<29)|((o.mask&0002)<<15)), everyoneSID))

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

				err = acl.Apply(name, true, inherit, grants...)
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

func takeOwnership(name string, owner *windows.SID, group *windows.SID) error {
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION|api.GROUP_SECURITY_INFORMATION,
		owner,
		group,
		0,
		0,
	)
}
