// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/features"

	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// New creates a new Agent and bootstrap the required subsystem.
func New(
	log *logger.Logger,
	baseLogger *logger.Logger,
	logLevel logp.Level,
	agentInfo *info.AgentInfo,
	reexec coordinator.ReExecManager,
	tracer *apm.Tracer,
<<<<<<< HEAD
=======
	testingMode bool,
	fleetInitTimeout time.Duration,
>>>>>>> 8a07dc8c0f (Increase timeout, add config for timeout in fleet setup (#2541))
	disableMonitoring bool,
	modifiers ...component.PlatformModifier,
) (*coordinator.Coordinator, composable.Controller, error) {
	platform, err := component.LoadPlatformDetail(modifiers...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	log.Info("Gathered system information")

	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	log.With("inputs", specs.Inputs()).Info("Detected available inputs and outputs")

	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}
	log.Info("Determined allowed capabilities")

	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// monitoring is not supported in bootstrap mode https://github.com/elastic/elastic-agent/issues/1761
	isMonitoringSupported := !disableMonitoring && cfg.Settings.V1MonitoringEnabled
	upgrader := upgrade.NewUpgrader(log, cfg.Settings.DownloadConfig, agentInfo)
	monitor := monitoring.New(isMonitoringSupported, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, agentInfo)

	runtime, err := runtime.NewManager(
		log,
		baseLogger,
		cfg.Settings.GRPC.String(),
		agentInfo,
		tracer,
		monitor,
		cfg.Settings.GRPC,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
	}

	var configMgr coordinator.ConfigManager
	var managed *managedConfigManager
	var compModifiers []coordinator.ComponentsModifier
	var composableManaged bool
	var isManaged bool
	if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is managed locally")

		loader := config.NewLoader(log, paths.ExternalInputs())
		discover := config.Discoverer(pathConfigFile, cfg.Settings.Path, paths.ExternalInputs())
		if !cfg.Settings.Reload.Enabled {
			log.Debug("Reloading of configuration is off")
			configMgr = newOnce(log, discover, loader)
		} else {
			log.Debugf("Reloading of configuration is on, frequency is set to %s", cfg.Settings.Reload.Period)
			configMgr = newPeriodic(log, cfg.Settings.Reload.Period, discover, loader)
		}
	} else {
		isManaged = true
		var store storage.Store
		store, cfg, err = mergeFleetConfig(rawConfig)
		if err != nil {
			return nil, nil, err
		}

		if configuration.IsFleetServerBootstrap(cfg.Fleet) {
			log.Info("Parsed configuration and determined agent is in Fleet Server bootstrap mode")

			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server))
			configMgr = newFleetServerBootstrapManager(log)
		} else {
			log.Info("Parsed configuration and determined agent is managed by Fleet")

			composableManaged = true
			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server),
				InjectFleetConfigComponentModifier(cfg.Fleet, agentInfo))

			managed, err = newManagedConfigManager(log, agentInfo, cfg, store, runtime, fleetInitTimeout)
			if err != nil {
				return nil, nil, err
			}
			configMgr = managed
		}
	}

	composable, err := composable.New(log, rawConfig, composableManaged)
	if err != nil {
		return nil, nil, errors.New(err, "failed to initialize composable controller")
	}

	coord := coordinator.New(log, logLevel, agentInfo, specs, reexec, upgrader, runtime, configMgr, composable, caps, monitor, isManaged, compModifiers...)
	if managed != nil {
		// the coordinator requires the config manager as well as in managed-mode the config manager requires the
		// coordinator, so it must be set here once the coordinator is created
		managed.coord = coord
	}

	// It is important that feature flags from configuration are applied as late as possible.  This will ensure that
	// any feature flag change callbacks are registered before they get called by `features.Apply`.
	if err := features.Apply(rawConfig); err != nil {
		return nil, nil, fmt.Errorf("could not parse and apply feature flags config: %w", err)
	}

	return coord, composable, nil
}

func mergeFleetConfig(rawConfig *config.Config) (storage.Store, *configuration.Configuration, error) {
	path := paths.AgentConfigFile()
	store := storage.NewEncryptedDiskStore(path)

	reader, err := store.Load()
	if err != nil {
		return store, nil, errors.New(err, "could not initialize config store",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}
	config, err := config.NewConfigFrom(reader)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to read configuration %s for the elastic-agent", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// merge local configuration and configuration persisted from fleet.
	err = rawConfig.Merge(config)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to merge configuration with %s for the elastic-agent", path),
			errors.TypeConfig,
			errors.M(errors.MetaKeyPath, path))
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return store, nil, errors.New(err,
			fmt.Sprintf("fail to unpack configuration from %s", path),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	// Fix up fleet.agent.id otherwise the fleet.agent.id is empty string
	if cfg.Settings != nil && cfg.Fleet != nil && cfg.Fleet.Info != nil && cfg.Fleet.Info.ID == "" {
		cfg.Fleet.Info.ID = cfg.Settings.ID
	}

	if err := cfg.Fleet.Valid(); err != nil {
		return store, nil, errors.New(err,
			"fleet configuration is invalid",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	return store, cfg, nil
}
