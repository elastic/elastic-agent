// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package paths

import (
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
)

// defaultAgentCapabilitiesFile is a name of file used to store agent capabilities
const defaultAgentCapabilitiesFile = "capabilities.yml"

// defaultAgentFleetYmlFile is a name of file used to store agent information
const defaultAgentFleetYmlFile = "fleet.yml"

// DefaultAgentFleetFile is a name of file used to store agent information encrypted
const DefaultAgentFleetFile = "fleet.enc"

// defaultAgentEnrollFile is a name of file used to enroll agent on first-start
const defaultAgentEnrollFile = "enroll.yml"

// defaultAgentActionStoreFile is the file that will contain the action that can
// be replayed after restart.
// It's deprecated and kept for migration purposes.
// Deprecated.
const defaultAgentActionStoreFile = "action_store.yml"

// defaultAgentStateStoreYmlFile is the file that will contain the action that
// can be replayed after restart.
// It's deprecated and kept for migration purposes.
// Deprecated.
const defaultAgentStateStoreYmlFile = "state.yml"

// defaultAgentStateStoreFile is the file that will contain the encrypted state
// store.
const defaultAgentStateStoreFile = "state.enc"

// AgentConfigYmlFile is a name of file used to store agent information
func AgentConfigYmlFile() string {
	return filepath.Join(Config(), defaultAgentFleetYmlFile)
}

// AgentConfigFile is a name of file used to store agent information
func AgentConfigFile() string {
	return filepath.Join(Config(), DefaultAgentFleetFile)
}

// AgentConfigFileLock is a locker for agent config file updates.
func AgentConfigFileLock() *filelock.AppLocker {
	return filelock.NewAppLocker(
		Config(),
		fmt.Sprintf("%s.lock", DefaultAgentFleetFile),
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

// AgentStateStoreYmlFile is the file that contains the persisted state of the agent including the action that can be replayed after restart.
func AgentStateStoreYmlFile() string {
	return filepath.Join(Home(), defaultAgentStateStoreYmlFile)
}

// AgentStateStoreFile is the file that contains the persisted state of the agent including the action that can be replayed after restart encrypted.
func AgentStateStoreFile() string {
	return filepath.Join(Home(), defaultAgentStateStoreFile)
}
