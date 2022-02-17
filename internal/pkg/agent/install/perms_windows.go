// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// +build windows

package install

import (
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// fixPermissions fixes the permissions so only SYSTEM and Administrators have access to the files in the install path
func fixPermissions() error {
	return recursiveSystemAdminPermissions(paths.InstallPath)
}

func recursiveSystemAdminPermissions(path string) error {
	return filepath.Walk(path, func(name string, info fs.FileInfo, err error) error {
		if err == nil {
			// first level doesn't inherit
			inherit := true
			if path == name {
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
	systemSID, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	administratorsSID, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}

	// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
	return acl.Apply(
		path, true, inherit,
		acl.GrantSid(0xF10F0000, systemSID), // full control of all acl's
		acl.GrantSid(0xF10F0000, administratorsSID))
}
