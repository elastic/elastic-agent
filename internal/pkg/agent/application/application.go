// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"fmt"
	"path/filepath"
	goruntime "runtime"
	"strconv"

	"github.com/elastic/go-sysinfo"
	"go.elastic.co/apm"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/dir"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type discoverFunc func() ([]string, error)

// ErrNoConfiguration is returned when no configuration are found.
var ErrNoConfiguration = errors.New("no configuration found", errors.TypeConfig)

// PlatformModifier can modify the platform details before the runtime specifications are loaded.
type PlatformModifier func(detail component.PlatformDetail) component.PlatformDetail

// New creates a new Agent and bootstrap the required subsystem.
func New(
	log *logger.Logger,
	agentInfo *info.AgentInfo,
	reexec coordinator.ReExecManager,
	tracer *apm.Tracer,
	modifiers ...PlatformModifier,
) (*coordinator.Coordinator, error) {
	platform, err := getPlatformDetail(modifiers...)
	if err != nil {
		return nil, fmt.Errorf("failed to gather system information: %w", err)
	}
	log.Info("Gathered system information")

	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}
	log.With("inputs", specs.Inputs()).Info("Detected available inputs and outputs")

	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log)
	if err != nil {
		return nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}
	log.Info("Determined allowed capabilities")

	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	upgrader := upgrade.NewUpgrader(log, cfg.Settings.DownloadConfig)

	var configMgr coordinator.ConfigManager
	var managed *managedConfigManager
	if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is managed locally")

		loader := config.NewLoader(log, externalConfigsGlob())
		discover := discoverer(pathConfigFile, cfg.Settings.Path, externalConfigsGlob())
		if !cfg.Settings.Reload.Enabled {
			log.Debug("Reloading of configuration is off")
			configMgr = newOnce(log, discover, loader)
		} else {
			log.Debugf("Reloading of configuration is on, frequency is set to %s", cfg.Settings.Reload.Period)
			configMgr = newPeriodic(log, cfg.Settings.Reload.Period, discover, loader)
		}
	} else if configuration.IsFleetServerBootstrap(cfg.Fleet) {
		log.Info("Parsed configuration and determined agent is in Fleet Server bootstrap mode")
		//	//return newFleetServerBootstrap(ctx, log, pathConfigFile, rawConfig, statusCtrl, agentInfo, tracer)
		//	return nil, errors.New("TODO: fleet-server bootstrap mode")
	} else {
		log.Info("Parsed configuration and determined agent is managed by Fleet")

		var store storage.Store
		store, cfg, err = mergeFleetConfig(rawConfig)
		if err != nil {
			return nil, err
		}

		managed, err = newManagedConfigManager(log, agentInfo, cfg, store)
		if err != nil {
			return nil, err
		}
		configMgr = managed
	}

	runtime, err := runtime.NewManager(log, cfg.Settings.GRPC.String(), tracer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
	}
	composable, err := composable.New(log, rawConfig)
	if err != nil {
		return nil, errors.New(err, "failed to initialize composable controller")
	}

	coord := coordinator.New(log, specs, reexec, upgrader, runtime, configMgr, composable, caps)
	if managed != nil {
		// the coordinator requires the config manager as well as in managed-mode the config manager requires the
		// coordinator, so it must be set here once the coordinator is created
		managed.coord = coord
	}
	return coord, nil
}

func getPlatformDetail(modifiers ...PlatformModifier) (component.PlatformDetail, error) {
	info, err := sysinfo.Host()
	if err != nil {
		return component.PlatformDetail{}, err
	}
	os := info.Info().OS
	detail := component.PlatformDetail{
		Platform: component.Platform{
			OS:   goruntime.GOOS,
			Arch: goruntime.GOARCH,
			GOOS: goruntime.GOOS,
		},
		Family: os.Family,
		Major:  strconv.Itoa(os.Major),
		Minor:  strconv.Itoa(os.Minor),
	}
	for _, modifier := range modifiers {
		detail = modifier(detail)
	}
	return detail, nil
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

	if err := cfg.Fleet.Valid(); err != nil {
		return store, nil, errors.New(err,
			"fleet configuration is invalid",
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, path))
	}

	return store, cfg, nil
}

func externalConfigsGlob() string {
	return filepath.Join(paths.Config(), configuration.ExternalInputsPattern)
}

func discoverer(patterns ...string) discoverFunc {
	var p []string
	for _, newP := range patterns {
		if len(newP) == 0 {
			continue
		}

		p = append(p, newP)
	}

	if len(p) == 0 {
		return func() ([]string, error) {
			return []string{}, ErrNoConfiguration
		}
	}

	return func() ([]string, error) {
		return dir.DiscoverFiles(p...)
	}
}
