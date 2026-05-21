// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/go-ucfg"
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
	if err := cfg.UnpackTo(c); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	// Hot reloading of TLS certificates is intentionally disabled in this release branch;
	// it will be enabled by default starting from the next minor release.
	disableTLSCertReload(c)

	return c, nil
}

func disableTLSCertReload(c *Configuration) {
	if c.Fleet == nil {
		return
	}
	disabled := false
	noReload := tlscommon.CertificateReload{Enabled: &disabled}
	if c.Fleet.Client.Transport.TLS != nil {
		c.Fleet.Client.Transport.TLS.CertificateReload = noReload
	}
	if c.Fleet.Server != nil {
		if c.Fleet.Server.TLS != nil {
			c.Fleet.Server.TLS.CertificateReload = noReload
		}
		if c.Fleet.Server.Output.Elasticsearch.TLS != nil {
			c.Fleet.Server.Output.Elasticsearch.TLS.CertificateReload = noReload
		}
	}
}

// NewPartialFromConfigNoDefaults creates a configuration based on common Config.
func NewPartialFromConfigNoDefaults(cfg *config.Config) (*Configuration, error) {
	c := new(Configuration)
	// Validator tag set to "validate_disable" is a hack to avoid validation errors on a partial config
	if err := cfg.UnpackTo(c, ucfg.ValidatorTag("validate_disable")); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	return c, nil
}

// AgentInfo is a set of agent information.
type AgentInfo struct {
	ID string `json:"id" yaml:"id" config:"id"`
}
