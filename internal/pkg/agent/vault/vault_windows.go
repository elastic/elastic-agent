// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package vault

import (
	"os"

	"github.com/billgraziano/dpapi"
	"github.com/hectane/go-acl"
	"golang.org/x/sys/windows"
)

func (v *Vault) encrypt(data []byte) ([]byte, error) {
	return dpapi.EncryptBytesMachineLocalEntropy(data, v.seed)
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	return dpapi.DecryptBytesEntropy(data, v.seed)
}

func tightenPermissions(path string) error {
	return systemAdministratorsOnly(path, false)
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

func writeFile(fp string, data []byte) (err error) {
	return os.WriteFile(fp, data, 0600)
}
