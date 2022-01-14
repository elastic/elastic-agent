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

package info

import (
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/release"
)

// AgentInfo is a collection of information about agent.
type AgentInfo struct {
	agentID  string
	logLevel string
	headers  map[string]string
}

// NewAgentInfoWithLog creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
// Initiates log level to predefined value.
func NewAgentInfoWithLog(level string, createAgentID bool) (*AgentInfo, error) {
	agentInfo, err := loadAgentInfoWithBackoff(false, level, createAgentID)
	if err != nil {
		return nil, err
	}

	return &AgentInfo{
		agentID:  agentInfo.ID,
		logLevel: agentInfo.LogLevel,
		headers:  agentInfo.Headers,
	}, nil
}

// NewAgentInfo creates a new agent information.
// In case when agent ID was already created it returns,
// this created ID otherwise it generates
// new unique identifier for agent.
// If agent config file does not exist it gets created.
func NewAgentInfo(createAgentID bool) (*AgentInfo, error) {
	return NewAgentInfoWithLog(defaultLogLevel, createAgentID)
}

// LogLevel retrieves a log level.
func (i *AgentInfo) LogLevel() string {
	if i.logLevel == "" {
		return logger.DefaultLogLevel.String()
	}
	return i.logLevel
}

// SetLogLevel updates log level of agent.
func (i *AgentInfo) SetLogLevel(level string) error {
	if err := updateLogLevel(level); err != nil {
		return err
	}

	i.logLevel = level
	return nil
}

// ReloadID reloads agent info ID from configuration file.
func (i *AgentInfo) ReloadID() error {
	newInfo, err := NewAgentInfoWithLog(i.logLevel, false)
	if err != nil {
		return err
	}
	i.agentID = newInfo.agentID
	return nil
}

// AgentID returns an agent identifier.
func (i *AgentInfo) AgentID() string {
	return i.agentID
}

// Version returns the version for this Agent.
func (*AgentInfo) Version() string {
	return release.Version()
}

// Snapshot returns if this version is a snapshot.
func (*AgentInfo) Snapshot() bool {
	return release.Snapshot()
}

// Headers returns custom headers used to communicate with elasticsearch.
func (i *AgentInfo) Headers() map[string]string {
	return i.headers
}
