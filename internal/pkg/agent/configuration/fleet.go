// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

// FleetAgentConfig is the internal configuration of the agent after the enrollment is done,
// this configuration is not exposed in anyway in the elastic-agent.yml and is only internal configuration.
type FleetAgentConfig struct {
	Enabled             bool               `config:"enabled" yaml:"enabled"`
	AccessAPIKey        string             `config:"access_api_key" yaml:"access_api_key"`
	ReplaceTokenHash    string             `config:"replace_token_hash" yaml:"replace_token_hash"`
	EnrollmentTokenHash string             `config:"enrollment_token_hash" yaml:"enrollment_token_hash"`
	Client              remote.Config      `config:",inline" yaml:",inline"`
	Info                *AgentInfo         `config:"agent" yaml:"agent"`
	Server              *FleetServerConfig `config:"server" yaml:"server,omitempty"`
	Checkin             FleetCheckin       `config:"checkin" yaml:"checkin,omitempty"`
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

		if err := e.Checkin.Validate(); err != nil {
			return err
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
		Checkin: DefaultFleetCheckin(),
	}
}

func DefaultFleetCheckin() FleetCheckin {
	return FleetCheckin{
		Mode: fleetCheckinModeStandard,
	}
}

type FleetCheckin struct {
	Mode               string        `config:"mode" yaml:"mode,omitempty"` // `standard` or `on_state_change` (empty string is accepted as standard)
	RequestBackoffInit time.Duration `config:"request_backoff_init" yaml:"request_backoff_init,omitempty"`
	RequestBackoffMax  time.Duration `config:"request_backoff_max" yaml:"request_backoff_max,omitempty"`
}

func (f *FleetCheckin) IsModeOnStateChanged() bool {
	return f.Mode == fleetCheckinModeOnStateChanged
}

func (f *FleetCheckin) Validate() error {
	if f.Mode != "" && f.Mode != fleetCheckinModeStandard && f.Mode != fleetCheckinModeOnStateChanged {
		return errors.New("checkin.mode must be either 'standard' or 'on_state_change'")
	}

	if f.RequestBackoffMax < f.RequestBackoffInit {
		return errors.New("checkin.request_backoff_max must be greater than or equal to checkin.request_backoff_init")
	}
	return nil
}

const (
	fleetCheckinModeStandard       = "standard"
	fleetCheckinModeOnStateChanged = "on_state_change"
)
