// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package vault

import (
	"os"

	"github.com/billgraziano/dpapi"
	"github.com/hectane/go-acl"
	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func (v *Vault) encrypt(data []byte) ([]byte, error) {
	return dpapi.EncryptBytesMachineLocalEntropy(data, v.seed)
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	return dpapi.DecryptBytesEntropy(data, v.seed)
}

func tightenPermissions(path string) error {
	systemSID, err := windows.StringToSid(utils.SystemSID)
	if err != nil {
		return err
	}
	administratorsSID, err := windows.StringToSid(utils.AdministratorSID)
	if err != nil {
		return err
	}
	acls := []api.ExplicitAccess{
		acl.GrantSid(0xF10F0000, systemSID),         // full control of all acl's
		acl.GrantSid(0xF10F0000, administratorsSID), // full control of all acl's
	}

	hasRoot, err := utils.HasRoot()
	if err == nil && !hasRoot {
		// ensure that the executing user also has rights
		ownership := utils.CurrentFileOwner()
		userSID, err := windows.StringToSid(ownership.UID)
		if err != nil {
			return err
		}
		acls = append(acls, acl.GrantSid(0xF10F0000, userSID))
	}

	return acl.Apply(path, true, false, acls...)
}

func writeFile(fp string, data []byte) error {
	return os.WriteFile(fp, data, 0600)
}
