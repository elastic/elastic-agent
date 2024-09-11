// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import "path/filepath"

const (

	// defaultAgentVaultName is keychain item name for keychain based vault (available on MacOS at the moment)
	defaultAgentVaultName = "co.elastic.elastic-agent"

	// defaultAgentVaultPath is the directory name where the file-based vault is located
	defaultAgentVaultPath = "vault"
)

// AgentVaultPath is the default path for file-based vault
func AgentVaultPath() string {
	return filepath.Join(Config(), defaultAgentVaultPath)
}

// AgentKeychainName is the default name for the keychain based vault
func AgentKeychainName() string {
	return defaultAgentVaultName
}
