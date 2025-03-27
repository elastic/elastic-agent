// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build windows

package perms

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/acl"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only SYSTEM and Administrators have access to the files in the install path
// Note that errors such as ERROR_FILE_NOT_FOUND and ERROR_PATH_NOT_FOUND are explicitly ignored
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
	grants := make([]acl.ExplicitAccess, 0, 4)
	grants = append(grants, acl.GrantSid(0xF10F0000, systemSID))         // full control of all acl's
	grants = append(grants, acl.GrantSid(0xF10F0000, administratorsSID)) // full control of all acl's

	// user gets grant based on the mask
	userSID := administratorsSID // defaults to owned by Administrators
	if o.mask&0700 != 0 && o.ownership.UID != "" {
		userSID, err = windows.StringToSid(o.ownership.UID)
		if err != nil {
			return fmt.Errorf("failed to get user %s: %w", o.ownership.UID, err)
		}
		grants = append(grants, acl.GrantSid(uint32(((o.mask&0700)<<23)|((o.mask&0200)<<9)), userSID))
	}

	// group gets grant based on the mask
	groupSID := administratorsSID // defaults to owned by Administrators
	if o.mask&0070 != 0 && o.ownership.GID != "" {
		groupSID, err = windows.StringToSid(o.ownership.GID)
		if err != nil {
			return fmt.Errorf("failed to get group %s: %w", o.ownership.GID, err)
		}
		grants = append(grants, acl.GrantSid(uint32(((o.mask&0070)<<26)|((o.mask&0020)<<12)), groupSID))
	}

	// everyone gets grant based on the mask
	if o.mask&0007 != 0 {
		everyoneSID, err := windows.StringToSid(utils.EveryoneSID)
		if err != nil {
			return fmt.Errorf("failed to get Everyone SID: %w", err)
		}
		grants = append(grants, acl.GrantSid(uint32(((o.mask&0007)<<29)|((o.mask&0002)<<15)), everyoneSID))
	}

	// ownership can only be change to another user when running as Administrator
	isAdmin, err := utils.HasRoot()
	if err != nil {
		return fmt.Errorf("failed to determine Administrator: %w", err)
	}
	if isAdmin {
		// since we are running as Administrator, we will change the ownership which requires SeRestorePrivilege
		return winio.RunWithPrivileges([]string{winio.SeRestorePrivilege}, func() error {
			return filepath.WalkDir(topPath, func(walkPath string, _ fs.DirEntry, err error) error {
				switch {
				case err == nil:
					// first level doesn't inherit
					inherit := topPath != walkPath
					return applyPermissions(walkPath, true, inherit, userSID, groupSID, grants...)
				case errors.Is(err, fs.ErrNotExist):
					return nil
				default:
					return err
				}
			})
		})
	}

	// ownership cannot be changed, this will keep the ownership as it currently is but apply the ACL's
	return filepath.WalkDir(topPath, func(walkPath string, _ fs.DirEntry, err error) error {
		switch {
		case err == nil:
			// first level doesn't inherit
			inherit := topPath != walkPath
			return applyPermissions(walkPath, true, inherit, nil, nil, grants...)
		case errors.Is(err, fs.ErrNotExist):
			return nil
		default:
			return err
		}
	})
}

// applyPermissions applies the provided access control entries to a path. When the given userSID or groupSID are not nil,
// it also sets the ownership information which requires the current process token to have the 'SeRestorePrivilege'.
// If you are not running as Administrator, pass nil for userSID and/or groupSID. Note that windows.ERROR_FILE_NOT_FOUND and
// windows.ERROR_PATH_NOT_FOUND are explicitly ignored.
func applyPermissions(path string, replace bool, inherit bool, userSID *windows.SID, groupSID *windows.SID, entries ...acl.ExplicitAccess) error {
	if err := acl.Apply(path, replace, inherit, entries...); err != nil {
		return filterNotFoundErrno(fmt.Errorf("apply ACL for %s failed: %w", path, err))
	}
	if userSID != nil && groupSID != nil {
		if err := acl.TakeOwnership(path, userSID, groupSID); err != nil {
			return filterNotFoundErrno(fmt.Errorf("take ownership for %s failed: %w", path, err))
		}
	}
	return nil
}

// filterNotFoundErrno returns the given error if it is not an ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND
func filterNotFoundErrno(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return nil
	case errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return nil
	default:
		return err
	}
}
