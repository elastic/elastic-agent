// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

type BackoffSettings struct {
	Init time.Duration `config:"init"`
	Max  time.Duration `config:"max"`
}

type FleetGatewaySettings struct {
	Debounce time.Duration   `config:"checkin.debounce" yaml:"checkin.debounce,omitempty"`   // time the agent has to wait before cancelling an ongoing checkin and start a new one
	Duration time.Duration   `config:"checkin.frequency" yaml:"checkin.frequency,omitempty"` // time between successful calls
	Jitter   time.Duration   `config:"jitter" yaml:"jitter,omitempty"`                       // used as a jitter for duration
	Backoff  BackoffSettings `config:"backoff" yaml:"backoff,omitempty"`                     // time after a failed call
}

// Returns default Configuration for the Fleet Gateway.
func DefaultFleetGatewaySettings() *FleetGatewaySettings {
	return &FleetGatewaySettings{
		Debounce: 5 * time.Minute,
		Duration: 1 * time.Second,
		Jitter:   500 * time.Millisecond,
		Backoff: BackoffSettings{
			Init: 60 * time.Second,
			Max:  10 * time.Minute,
		},
	}
}

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
