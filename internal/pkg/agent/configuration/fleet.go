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

package configuration

import (
	"github.com/elastic/elastic-agent-poc/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent-poc/internal/pkg/remote"
	fleetreporterConfig "github.com/elastic/elastic-agent-poc/internal/pkg/reporter/fleet/config"
)

// FleetAgentConfig is the internal configuration of the agent after the enrollment is done,
// this configuration is not exposed in anyway in the elastic-agent.yml and is only internal configuration.
type FleetAgentConfig struct {
	Enabled      bool                        `config:"enabled" yaml:"enabled"`
	AccessAPIKey string                      `config:"access_api_key" yaml:"access_api_key"`
	Client       remote.Config               `config:",inline" yaml:",inline"`
	Reporting    *fleetreporterConfig.Config `config:"reporting" yaml:"reporting"`
	Info         *AgentInfo                  `config:"agent" yaml:"agent"`
	Server       *FleetServerConfig          `config:"server" yaml:"server,omitempty"`
}

// Valid validates the required fields for accessing the API.
func (e *FleetAgentConfig) Valid() error {
	if e.Enabled {
		if e.Server != nil && e.Server.Bootstrap {
			// bootstrapping Fleet Server, checks below can be ignored
			return nil
		}

		if len(e.AccessAPIKey) == 0 {
			return errors.New("empty access token", errors.TypeConfig)
		}

		if len(e.Client.Host) == 0 {
			return errors.New("missing fleet host configuration", errors.TypeConfig)
		}
	}

	return nil
}

// DefaultFleetAgentConfig creates a default configuration for fleet.
func DefaultFleetAgentConfig() *FleetAgentConfig {
	return &FleetAgentConfig{
		Enabled:   false,
		Client:    remote.DefaultClientConfig(),
		Reporting: fleetreporterConfig.DefaultConfig(),
		Info:      &AgentInfo{},
	}
}
