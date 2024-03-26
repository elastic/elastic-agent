// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package vault

import (
	"os"

	"github.com/billgraziano/dpapi"

	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func (v *FileVault) encrypt(data []byte) ([]byte, error) {
	return dpapi.EncryptBytesMachineLocalEntropy(data, v.seed)
}

func (v *FileVault) decrypt(data []byte) ([]byte, error) {
	return dpapi.DecryptBytesEntropy(data, v.seed)
}

func tightenPermissions(path string, ownership utils.FileOwner) error {
	return perms.FixPermissions(path, perms.WithMask(0750), perms.WithOwnership(ownership))
}

func writeFile(fp string, data []byte) error {
	return os.WriteFile(fp, data, 0600)
}
