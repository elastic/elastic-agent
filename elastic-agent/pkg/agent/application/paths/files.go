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

package paths

import (
	"fmt"
	"path/filepath"

	"github.com/elastic/elastic-agent-poc/elastic-agent/pkg/agent/application/filelock"
)

// defaultAgentCapabilitiesFile is a name of file used to store agent capabilities
const defaultAgentCapabilitiesFile = "capabilities.yml"

// defaultAgentFleetFile is a name of file used to store agent information
const defaultAgentFleetFile = "fleet.yml"

// defaultAgentEnrollFile is a name of file used to enroll agent on first-start
const defaultAgentEnrollFile = "enroll.yml"

// defaultAgentActionStoreFile is the file that will contains the action that can be replayed after restart.
const defaultAgentActionStoreFile = "action_store.yml"

// defaultAgentStateStoreFile is the file that will contains the action that can be replayed after restart.
const defaultAgentStateStoreFile = "state.yml"

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
