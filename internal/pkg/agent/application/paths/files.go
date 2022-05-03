// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package paths

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
)

// defaultAgentCapabilitiesFile is a name of file used to store agent capabilities
const defaultAgentCapabilitiesFile = "capabilities.yml"

// defaultAgentFleetFile is a name of file used to store agent information
const defaultAgentFleetFile = "fleet.yml"

// defaultAgentEnrollFile is a name of file used to enroll agent on first-start
const defaultAgentEnrollFile = "enroll.yml"

// defaultAgentActionStoreFile is the file that will contain the action that can be replayed after restart.
const defaultAgentActionStoreFile = "action_store.yml"

// defaultAgentStateStoreFile is the file that will contain the action that can be replayed after restart.
const defaultAgentStateStoreFile = "state.yml"

// defaultAgentVaultPath is the directory for windows and linux where the vault store is located or the keychain item name for mac
const defaultAgentVaultPath = "co.elastic.agent"

// AgentConfigFile is a name of file used to store agent information
func AgentConfigFile() string {
	return filepath.Join(Config(), defaultAgentFleetFile)
}

// AgentConfigFileLock is a locker for agent config file updates.
func AgentConfigFileLock() *filelock.AppLocker {
	return filelock.NewAppLocker(
		Config(),
		fmt.Sprintf("%s.lock", defaultAgentFleetFile),
	)
}

// AgentEnrollFile is a name of file used to enroll agent on first-start
func AgentEnrollFile() string {
	return filepath.Join(Config(), defaultAgentEnrollFile)
}

// AgentCapabilitiesPath is a name of file used to store agent capabilities
func AgentCapabilitiesPath() string {
	return filepath.Join(Config(), defaultAgentCapabilitiesFile)
}

// AgentActionStoreFile is the file that contains the action that can be replayed after restart.
func AgentActionStoreFile() string {
	return filepath.Join(Home(), defaultAgentActionStoreFile)
}

// AgentStateStoreFile is the file that contains the persisted state of the agent including the action that can be replayed after restart.
func AgentStateStoreFile() string {
	return filepath.Join(Home(), defaultAgentStateStoreFile)
}

// AgentVaultPath is the directory that contains all the files for the value for windows and linux
func AgentVaultPath() string {
	if runtime.GOOS == "darwin" {
		return defaultAgentVaultPath
	}
	return filepath.Join(Home(), "vault", defaultAgentVaultPath)
}
