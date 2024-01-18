// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux

package paths

import "path/filepath"

const (
	// ControlSocketRunSymlink is the path to the symlink that should be
	// created to the control socket when Elastic Agent is running with root.
	ControlSocketRunSymlink = "/run/elastic-agent.sock"

	// defaultAgentVaultPath is the directory for linux where the vault store is located or the
	defaultAgentVaultPath = "vault"
)

// AgentVaultPath is the directory that contains all the files for the value
func AgentVaultPath() string {
	return filepath.Join(Config(), defaultAgentVaultPath)
}
