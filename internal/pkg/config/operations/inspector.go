// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package operations

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage/store"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

var (
	// ErrNoFleetConfig is returned when no configuration was retrieved from fleet just yet.
	ErrNoFleetConfig = fmt.Errorf("no fleet config retrieved yet")
)

// LoadFullAgentConfig load agent config based on provided paths and defined capabilities.
// In case fleet is used, config from policy action is returned.
func LoadFullAgentConfig(ctx context.Context, logger *logger.Logger, cfgPath string, failOnFleetMissing, unprivileged bool) (*config.Config, error) {
	rawConfig, err := loadConfig(ctx, cfgPath, unprivileged)
	if err != nil {
		return nil, fmt.Errorf("error loading raw config: %w", err)
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating config object from raw agent config: %w", err)
	}

	if configuration.IsStandalone(cfg.Fleet) {
		// When in standalone we load the configuration again with inputs that are defined in the paths.ExternalInputs.
		loader := config.NewLoader(logger, paths.ExternalInputs())
		discover := config.Discoverer(cfgPath, cfg.Settings.Path, paths.ExternalInputs())
		files, err := discover()
		if err != nil {
			return nil, fmt.Errorf("could not discover configuration files: %w", err)
		}
		if len(files) == 0 {
			return nil, config.ErrNoConfiguration
		}
		c, err := loader.Load(files)
		if err != nil {
			return nil, fmt.Errorf("failed to load or merge configuration: %w", err)
		}
		return c, nil
	}

	fleetConfig, err := loadFleetConfig(ctx, logger, unprivileged)
	if err != nil {
		return nil, fmt.Errorf("error obtaining fleet config: %w", err)
	} else if fleetConfig == nil {
		if failOnFleetMissing {
			return nil, ErrNoFleetConfig
		}

		// resolving fleet config but not fleet config retrieved yet, returning last applied config
		return rawConfig, nil
	}

	// merge the policy on top of the configuration to provide a unified configuration
	err = rawConfig.Merge(fleetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to merge latest fleet policy with local configuration: %w", err)
	}
	return rawConfig, nil
}

func loadConfig(ctx context.Context, configPath string, unprivileged bool) (*config.Config, error) {
	rawConfig, err := config.LoadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config file %s: %w", configPath, err)
	}

	path := paths.AgentConfigFile()

	store, err := storage.NewEncryptedDiskStore(ctx, path, storage.WithUnprivileged(unprivileged))
	if err != nil {
		return nil, fmt.Errorf("error instantiating encrypted disk store: %w", err)
	}
	reader, err := store.Load()
	if err != nil {
		return nil, errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	config, err := config.NewConfigFrom(reader)
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// merge local configuration and configuration persisted from fleet.
	err = rawConfig.Merge(config)
	if err != nil {
		return nil, fmt.Errorf("error merging local and fleet config: %w", err)
	}

	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, fmt.Errorf("error injecting agent config: %w", err)
	}

	return rawConfig, nil
}

func loadFleetConfig(ctx context.Context, l *logger.Logger, unprivileged bool) (map[string]interface{}, error) {
	stateStore, err := store.NewStateStoreWithMigration(ctx, l, paths.AgentActionStoreFile(), paths.AgentStateStoreFile(), storage.WithUnprivileged(unprivileged))
	if err != nil {
		return nil, err
	}

	cfgChange, ok := stateStore.Action().(*fleetapi.ActionPolicyChange)
	if ok {
		return cfgChange.Data.Policy, nil
	}

	return nil, nil
}
