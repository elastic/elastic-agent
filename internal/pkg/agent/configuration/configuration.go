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

// ConfigReloader reloads the applied configuration while preserving the startup configuration.
type ConfigReloader struct {
	startupConfig  *Configuration
	config         *Configuration
	configOverride CfgOverrider
}

// NewConfigReloader loads the startup and applied configurations.
func NewConfigReloader(ctx context.Context, startupOverride, configOverride CfgOverrider) (*ConfigReloader, error) {
	uCfg, err := loadLocalConfig()
	if err != nil {
		return nil, err
	}
	managed, _ := uCfg.Agent.Bool("fleet.enabled", -1, ucfg.PathSep("."))

	if startupOverride != nil {
		if err := startupOverride(uCfg); err != nil {
			return nil, errors.New(err, "could not apply startup config override")
		}
	}

	if err := info.InjectAgentConfig(uCfg); err != nil {
		return nil, errors.New(err, "could not inject agent path/host/runtime config")
	}

	startupConfig, err := NewFromConfig(uCfg)
	if err != nil {
		return nil, errors.New(err, "could not parse startup agent configuration")
	}

	config, err := mergeAppliedConfiguration(ctx, startupConfig, managed, configOverride)
	if err != nil {
		return nil, err
	}

	return &ConfigReloader{
		startupConfig:  startupConfig,
		config:         config,
		configOverride: configOverride,
	}, nil
}

// Reload updates the applied configuration.
func (r *ConfigReloader) Reload(ctx context.Context) error {
	current, err := loadLocalConfig()
	if err != nil {
		return err
	}

	managed, _ := current.Agent.Bool("fleet.enabled", -1, ucfg.PathSep("."))

	cfg, err := mergeAppliedConfiguration(ctx, r.startupConfig, managed, r.configOverride)
	if err != nil {
		return err
	}
	r.config = cfg
	return nil
}

// StartupConfiguration returns the configuration captured at startup.
func (r *ConfigReloader) StartupConfiguration() *Configuration {
	return r.startupConfig
}

// Configuration returns the applied configuration.
func (r *ConfigReloader) Configuration() *Configuration {
	return r.config
}

func loadLocalConfig() (*config.Config, error) {
	path := paths.ConfigFile()
	uCfg, err := config.LoadFile(path)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}
	return uCfg, nil
}

func loadFleetConfig(ctx context.Context) (*config.Config, error) {
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

func mergeAppliedConfiguration(ctx context.Context, startupConfig *Configuration, managed bool, configOverride CfgOverrider) (*Configuration, error) {
	uCfg, err := startupConfig.GetUCfg().Clone()
	if err != nil {
		return nil, errors.New(err, "could not clone startup configuration")
	}

	if managed {
		fleetCfg, err := loadFleetConfig(ctx)
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

	if err := uCfg.Agent.SetBool("fleet.enabled", -1, managed, ucfg.PathSep(".")); err != nil {
		return nil, errors.New(err, "could not apply agent mode")
	}

	if configOverride != nil {
		if err := configOverride(uCfg); err != nil {
			return nil, errors.New(err, "could not apply config override")
		}
	}

	cfg, err := NewFromConfig(uCfg)
	if err != nil {
		return nil, errors.New(err, "could not parse agent configuration")
	}

	return cfg, nil
}
