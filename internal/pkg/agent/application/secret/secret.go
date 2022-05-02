// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package secret

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

const agentSecretKey = "secret"

// Create creates agent secret and stores it in the vault
func Create() error {
	v, err := vault.New(paths.AgentVaultPath())
	if err != nil {
		return err
	}
	defer v.Close()

	// Check if the key exists
	exists, err := v.Exists(agentSecretKey)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// Create new AES256 key
	k, err := vault.NewKey(vault.AES256)
	if err != nil {
		return err
	}

	return v.Set(agentSecretKey, k)
}

// Get reads the secret key from the vault
func Get() ([]byte, error) {
	v, err := vault.New(paths.AgentVaultPath())
	if err != nil {
		return nil, err
	}
	defer v.Close()
	return v.Get(agentSecretKey)
}
