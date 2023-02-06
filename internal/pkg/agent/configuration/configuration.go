// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package configuration

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
)

// Configuration is a overall agent configuration
type Configuration struct {
	Fleet    *FleetAgentConfig `config:"fleet"  yaml:"fleet" json:"fleet"`
	Settings *SettingsConfig   `config:"agent"  yaml:"agent" json:"agent"`
}

// DefaultConfiguration creates a configuration prepopulated with default values.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		Fleet:    DefaultFleetAgentConfig(),
		Settings: DefaultSettingsConfig(),
	}
}

// NewFromConfig creates a configuration based on common Config.
func NewFromConfig(cfg *config.Config) (*Configuration, error) {
	c := DefaultConfiguration()
	if err := cfg.Unpack(c); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	return c, nil
}

// AgentInfo is a set of agent information.
type AgentInfo struct {
	ID string `json:"id" yaml:"id" config:"id"`
}
