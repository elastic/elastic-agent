// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/go-sysinfo"
	"go.elastic.co/apm"
	goruntime "runtime"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
	"github.com/elastic/elastic-agent/internal/pkg/sorted"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/reexec"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// PlatformModifier can modify the platform details before the runtime specifications are loaded.
type PlatformModifier func(detail component.PlatformDetail) component.PlatformDetail

// Application is the application interface implemented by the different running mode.
type Application interface {
	Run(ctx context.Context) error
	AgentInfo() *info.AgentInfo
	Routes() *sorted.Set
}

type reexecManager interface {
	ReExec(callback reexec.ShutdownCallbackFn, argOverrides ...string)
}

type upgraderControl interface {
	SetUpgrader(upgrader *upgrade.Upgrader)
}

// New creates a new Agent and bootstrap the required subsystem.
func New(
	log *logger.Logger,
	reexec reexecManager,
	statusCtrl status.Controller,
	uc upgraderControl,
	agentInfo *info.AgentInfo,
	tracer *apm.Tracer,
	modifiers ...PlatformModifier,
) (Application, error) {
	log.Info("Gathering system information")
	platform, err := getPlatformDetail(modifiers...)
	if err != nil {
		return nil, fmt.Errorf("failed to gather system information: %w", err)
	}

	log.Info("Detecting available inputs and outputs")
	specs, err := component.LoadRuntimeSpecs(paths.Components(), platform)
	if err != nil {
		return nil, fmt.Errorf("failed to detect inputs and outputs: %w", err)
	}

	log.Info("Determine allowed capabilities")
	caps, err := capabilities.Load(paths.AgentCapabilitiesPath(), log, statusCtrl)
	if err != nil {
		return nil, fmt.Errorf("failed to determine capabilities: %w", err)
	}

	log.Info("Parsing configuration and determining execution mode")
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

	if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Agent is managed locally")
		return newLocal(log, specs, caps, cfg, paths.ConfigFile(), rawConfig, reexec, statusCtrl, uc, agentInfo, tracer)
	}

	// not in standalone; both modes require reading the fleet.yml configuration file
	//var store storage.Store
	//store, cfg, err = mergeFleetConfig(rawConfig)
	//if err != nil {
	//	return nil, err
	//}

	if configuration.IsFleetServerBootstrap(cfg.Fleet) {
		log.Info("Agent is in Fleet Server bootstrap mode")
		//return newFleetServerBootstrap(ctx, log, pathConfigFile, rawConfig, statusCtrl, agentInfo, tracer)
		return nil, errors.New("TODO: fleet-server bootstrap mode")
	}

	log.Info("Agent is managed by Fleet")
	//return newManaged(ctx, log, store, cfg, rawConfig, reexec, statusCtrl, agentInfo, tracer)
	return nil, errors.New("TODO: fleet mode")
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
