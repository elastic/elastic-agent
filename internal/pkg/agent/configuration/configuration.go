// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"context"
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/go-ucfg"
)

// CfgOverrider allows for application-driven overrides of the raw config before it is parsed.
type CfgOverrider func(cfg *config.Config) error

// Configuration is a overall agent configuration
type Configuration struct {
	Fleet    *FleetAgentConfig `config:"fleet"  yaml:"fleet" json:"fleet"`
	Settings *SettingsConfig   `config:"agent"  yaml:"agent" json:"agent"`
	UCfg     *config.Config    `config:"-"      yaml:"-"     json:"-"`
}

// DefaultConfiguration creates a configuration prepopulated with default values.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		Fleet:    DefaultFleetAgentConfig(),
		Settings: DefaultSettingsConfig(),
	}
}

// GetUCfg returns the raw config, initializing it from the structured fields if nil.
func (c *Configuration) GetUCfg() *config.Config {
	if c.UCfg == nil {
		c.UCfg = config.MustNewConfigFrom(c)
	}
	return c.UCfg
}

// NewFromConfig creates a configuration based on common Config.
func NewFromConfig(cfg *config.Config) (*Configuration, error) {
	c := DefaultConfiguration()
	if err := cfg.UnpackTo(c); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}
	c.UCfg = cfg
	return c, nil
}

// NewPartialFromConfigNoDefaults creates a configuration based on common Config.
func NewPartialFromConfigNoDefaults(cfg *config.Config) (*Configuration, error) {
	c := new(Configuration)
	// Validator tag set to "validate_disable" is a hack to avoid validation errors on a partial config
	if err := cfg.UnpackTo(c, ucfg.ValidatorTag("validate_disable"), ucfg.PathSep(".")); err != nil {
		return nil, errors.New(err, errors.TypeConfig)
	}

	return c, nil
}

// AgentInfo is a set of agent information.
type AgentInfo struct {
	ID string `json:"id" yaml:"id" config:"id"`
}

func LoadConfig(ctx context.Context, override CfgOverrider) (*Configuration, error) {
	uCfg, err := loadBaseFileConfig()
	if err != nil {
		return nil, err
	}

	loadFleet, _ := uCfg.Agent.Bool("fleet.enabled", -1, ucfg.PathSep("."))
	if loadFleet {
		fleetCfg, err := loadFleetFileConfig(ctx)
		if err != nil {
			return nil, err
		}
		if fleetCfg != nil {
			if err := uCfg.Merge(fleetCfg); err != nil {
				return nil, errors.New(err, "could not merge fleet configuration",
					errors.TypeConfig,
					errors.M(errors.MetaKeyPath, paths.AgentConfigFile()))
			}
		}
	}

	if err := info.InjectAgentConfig(uCfg); err != nil {
		return nil, errors.New(err, "could not inject agent path/host/runtime config")
	}

	if override != nil {
		if err := override(uCfg); err != nil {
			return nil, errors.New(err, "could not apply config override")
		}
	}

	cfg, err := NewFromConfig(uCfg)
	if err != nil {
		return nil, errors.New(err, "could not parse agent configuration")
	}

	return cfg, nil
}

func loadBaseFileConfig() (*config.Config, error) {
	pathConfigFile := paths.ConfigFile()
	uCfg, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}
	return uCfg, nil
}

func loadFleetFileConfig(ctx context.Context) (*config.Config, error) {
	path := paths.AgentConfigFile()
	store, err := storage.NewEncryptedDiskStore(ctx, path)
	if err != nil {
		return nil, errors.New(err, "could not create encrypted disk store")
	}

	reader, err := store.Load()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	fleetCfg, err := config.NewConfigFrom(reader)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// Fix up fleet.agent.id otherwise the fleet.agent.id is empty string
	if fleetAgentID, _ := fleetCfg.Agent.String("fleet.agent.id", -1, ucfg.PathSep(".")); fleetAgentID == "" {
		if agentID, err := fleetCfg.Agent.String("agent.id", -1, ucfg.PathSep(".")); err == nil && agentID != "" {
			_ = fleetCfg.Agent.SetString("fleet.agent.id", -1, agentID, ucfg.PathSep("."))
		}
	}

	return fleetCfg, nil
}
