// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// FixPermissions fixes the permissions so only SYSTEM and Administrators have access to the files in the install path
func FixPermissions(topPath string, ownership utils.FileOwner) error {
	return filepath.Walk(topPath, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// first level doesn't inherit
			inherit := true
			if topPath == name {
				inherit = false
			}
			err = systemAdministratorsOnly(name, inherit)
		} else if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	})
}

func systemAdministratorsOnly(path string, inherit bool) error {
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	systemSID, err := windows.StringToSid(utils.SystemSID)
	if err != nil {
		return err
	}
	administratorsSID, err := windows.StringToSid(utils.AdministratorSID)
	if err != nil {
		return err
	}

	// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
	return acl.Apply(
		path, true, inherit,
		acl.GrantSid(0xF10F0000, systemSID), // full control of all acl's
		acl.GrantSid(0xF10F0000, administratorsSID))
}
