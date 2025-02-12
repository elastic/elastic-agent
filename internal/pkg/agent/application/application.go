// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"context"
	"fmt"
	"time"

	"go.elastic.co/apm/v2"

	"github.com/elastic/elastic-agent-libs/logp"

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
	"github.com/elastic/elastic-agent/internal/pkg/composable/providers/kubernetes"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	otelmanager "github.com/elastic/elastic-agent/internal/pkg/otel/manager"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/features"
	"github.com/elastic/elastic-agent/pkg/limits"
	"github.com/elastic/elastic-agent/version"
)

// CfgOverrider allows for application driven overrides of configuration read from disk.
type CfgOverrider func(cfg *configuration.Configuration)

// New creates a new Agent and bootstrap the required subsystem.
func New(
	ctx context.Context,
	log *logger.Logger,
	baseLogger *logger.Logger,
	logLevel logp.Level,
	agentInfo info.Agent,
	reexec coordinator.ReExecManager,
	tracer *apm.Tracer,
	testingMode bool,
	fleetInitTimeout time.Duration,
	disableMonitoring bool,
	override CfgOverrider,
	modifiers ...component.PlatformModifier,
) (*coordinator.Coordinator, coordinator.ConfigManager, composable.Controller, error) {

	err := version.InitVersionError()
	if err != nil {
		// non-fatal error, log a warning and move on
		log.With("error.message", err).Warnf("Error initializing version information: falling back to %s", release.Version())
	}

	platform, err := component.LoadPlatformDetail(modifiers...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	log.Info("Gathered system information")

	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	log.With("inputs", specs.Inputs()).Info("Detected available inputs and outputs")

	caps, err := capabilities.LoadFile(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}
	log.Info("Determined allowed capabilities")

	pathConfigFile := paths.ConfigFile()

	var rawConfig *config.Config
	if testingMode {
		// testing mode doesn't read any configuration from the disk
		rawConfig, err = config.NewConfigFrom("")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
		}

		// monitoring is always disabled in testing mode
		disableMonitoring = true
	} else {
		log.Infof("Loading baseline config from %v", pathConfigFile)
		rawConfig, err = config.LoadFile(pathConfigFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
		}
	}
	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	if override != nil {
		override(cfg)
	}

	// monitoring is not supported in bootstrap mode https://github.com/elastic/elastic-agent/issues/1761
	isMonitoringSupported := !disableMonitoring && cfg.Settings.V1MonitoringEnabled
	upgrader, err := upgrade.NewUpgrader(log, cfg.Settings.DownloadConfig, agentInfo)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create upgrader: %w", err)
	}
	monitor := monitoring.New(isMonitoringSupported, cfg.Settings.DownloadConfig.OS(), cfg.Settings.MonitoringConfig, agentInfo)

	runtime, err := runtime.NewManager(
		log,
		baseLogger,
		agentInfo,
		tracer,
		monitor,
		cfg.Settings.GRPC,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
	}

	var configMgr coordinator.ConfigManager
	var managed *managedConfigManager
	var compModifiers = []coordinator.ComponentsModifier{InjectAPMConfig}
	var composableManaged bool
	var isManaged bool

	if testingMode {
		log.Info("Elastic Agent has been started in testing mode and is managed through the control protocol")

		// testing mode uses a config manager that takes configuration from over the control protocol
		configMgr = newTestingModeConfigManager(log)
	} else if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is managed locally")

		loader := config.NewLoader(log, paths.ExternalInputs())
		rawCfgMap, err := rawConfig.ToMapStr()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to transform agent configuration into a map: %w", err)
		}
		discover := config.Discoverer(pathConfigFile, cfg.Settings.Path, paths.ExternalInputs(),
			kubernetes.GetHintsInputConfigPath(log, rawCfgMap))
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
		store, cfg, err = mergeFleetConfig(ctx, rawConfig)
		if err != nil {
			return nil, nil, nil, err
		}
		if configuration.IsFleetServerBootstrap(cfg.Fleet) {
			log.Info("Parsed configuration and determined agent is in Fleet Server bootstrap mode")

			compModifiers = append(compModifiers, FleetServerComponentModifier(cfg.Fleet.Server))
			configMgr = coordinator.NewConfigPatchManager(newFleetServerBootstrapManager(log), PatchAPMConfig(log, rawConfig))
		} else {
			log.Info("Parsed configuration and determined agent is managed by Fleet")

			composableManaged = true
			compModifiers = append(compModifiers,
				FleetServerComponentModifier(cfg.Fleet.Server),
				InjectFleetConfigComponentModifier(cfg.Fleet, agentInfo),
				EndpointSignedComponentModifier(),
				EndpointTLSComponentModifier(log),
				InjectProxyEndpointModifier(),
			)

			// TODO: stop using global state
			managed, err = newManagedConfigManager(ctx, log, agentInfo, cfg, store, runtime, fleetInitTimeout, paths.Top(), upgrader)
			if err != nil {
				return nil, nil, nil, err
			}
			configMgr = coordinator.NewConfigPatchManager(managed, PatchAPMConfig(log, rawConfig))
		}
	}

	varsManager, err := composable.New(log, rawConfig, composableManaged)
	if err != nil {
		return nil, nil, nil, errors.New(err, "failed to initialize composable controller")
	}

	otelManager := otelmanager.NewOTelManager(log.Named("otel_manager"))
	coord := coordinator.New(log, cfg, logLevel, agentInfo, specs, reexec, upgrader, runtime, configMgr, varsManager, caps, monitor, isManaged, otelManager, compModifiers...)
	if managed != nil {
		// the coordinator requires the config manager as well as in managed-mode the config manager requires the
		// coordinator, so it must be set here once the coordinator is created
		managed.coord = coord
	}

	// every time we change the limits we'll see the log message
	limits.AddLimitsOnChangeCallback(func(new, old limits.LimitsConfig) {
		log.Debugf("agent limits have changed: %+v -> %+v", old, new)
	}, "application.go")
	// applying the initial limits for the agent process
	if err := limits.Apply(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse and apply limits config: %w", err)
	}

	// It is important that feature flags from configuration are applied as late as possible.  This will ensure that
	// any feature flag change callbacks are registered before they get called by `features.Apply`.
	if err := features.Apply(rawConfig); err != nil {
		return nil, nil, nil, fmt.Errorf("could not parse and apply feature flags config: %w", err)
	}

	return coord, configMgr, varsManager, nil
}

func mergeFleetConfig(ctx context.Context, rawConfig *config.Config) (storage.Store, *configuration.Configuration, error) {
	path := paths.AgentConfigFile()
	store, err := storage.NewEncryptedDiskStore(ctx, path)
	if err != nil {
		return nil, nil, fmt.Errorf("error instantiating encrypted disk store: %w", err)
	}

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
