// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

// FleetAgentConfig is the internal configuration of the agent after the enrollment is done,
// this configuration is not exposed in anyway in the elastic-agent.yml and is only internal configuration.
type FleetAgentConfig struct {
	Enabled      bool               `config:"enabled" yaml:"enabled"`
	AccessAPIKey string             `config:"access_api_key" yaml:"access_api_key"`
	Client       remote.Config      `config:",inline" yaml:",inline"`
	Info         *AgentInfo         `config:"agent" yaml:"agent"`
	Server       *FleetServerConfig `config:"server" yaml:"server,omitempty"`
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
		Enabled: false,
		Client:  remote.DefaultClientConfig(),
		Info:    &AgentInfo{},
	}
}
