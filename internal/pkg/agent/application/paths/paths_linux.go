// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package paths

import "path/filepath"

// defaultAgentVaultPath is the directory for linux where the vault store is located or the
const defaultAgentVaultPath = "vault"

// AgentVaultPath is the directory that contains all the files for the value
func AgentVaultPath() string {
	return filepath.Join(Config(), defaultAgentVaultPath)
}
