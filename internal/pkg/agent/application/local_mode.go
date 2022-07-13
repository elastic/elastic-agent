// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package application

import (
	"context"
	"fmt"
	"go.elastic.co/apm"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/capabilities"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
	"github.com/elastic/elastic-agent/internal/pkg/dir"
	acker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/internal/pkg/sorted"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type discoverFunc func() ([]string, error)

// ErrNoConfiguration is returned when no configuration are found.
var ErrNoConfiguration = errors.New("no configuration found", errors.TypeConfig)

// Local represents a standalone agents, that will read his configuration directly from disk.
// Some part of the configuration can be reloaded.
type Local struct {
	log         *logger.Logger
	agentInfo   *info.AgentInfo
	caps        capabilities.Capability
	reexec      reexecManager
	uc          upgraderControl
	downloadCfg *artifact.Config

	runtime    coordinator.RuntimeManager
	config     coordinator.ConfigManager
	composable coordinator.VarsManager

	coordinator *coordinator.Coordinator
}

// newLocal return an agent managed by local configuration.
func newLocal(
	log *logger.Logger,
	specs component.RuntimeSpecs,
	caps capabilities.Capability,
	cfg *configuration.Configuration,
	pathConfigFile string,
	rawConfig *config.Config,
	reexec reexecManager,
	statusCtrl status.Controller,
	uc upgraderControl,
	agentInfo *info.AgentInfo,
	tracer *apm.Tracer,
) (*Local, error) {
	localApplication := &Local{
		log:         log,
		agentInfo:   agentInfo,
		caps:        caps,
		reexec:      reexec,
		uc:          uc,
		downloadCfg: cfg.Settings.DownloadConfig,
	}

	loader := config.NewLoader(log, externalConfigsGlob())
	discover := discoverer(pathConfigFile, cfg.Settings.Path, externalConfigsGlob())
	if !cfg.Settings.Reload.Enabled {
		log.Debug("Reloading of configuration is off")
		localApplication.config = newOnce(log, discover, loader)
	} else {
		log.Debugf("Reloading of configuration is on, frequency is set to %s", cfg.Settings.Reload.Period)
		localApplication.config = newPeriodic(log, cfg.Settings.Reload.Period, discover, loader)
	}

	var err error
	localApplication.runtime, err = runtime.NewManager(log, cfg.Settings.GRPC.String(), tracer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize runtime manager: %w", err)
	}
	localApplication.composable, err = composable.New(log, rawConfig)
	if err != nil {
		return nil, errors.New(err, "failed to initialize composable controller")
	}

	localApplication.coordinator = coordinator.New(log, specs, localApplication.runtime, localApplication.config, localApplication.composable, caps)

	return localApplication, nil
}

func externalConfigsGlob() string {
	return filepath.Join(paths.Config(), configuration.ExternalInputsPattern)
}

// Routes returns a list of routes handled by agent.
func (l *Local) Routes() *sorted.Set {
	return nil
}

// Run runs the local agent.
//
// Blocks until the context is cancelled.
func (l *Local) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)

	u := upgrade.NewUpgrader(
		l.agentInfo,
		l.downloadCfg,
		l.log,
		[]context.CancelFunc{cancel},
		l.reexec,
		acker.NewAcker(),
		nil,
		l.caps)
	l.uc.SetUpgrader(u)

	err := l.coordinator.Run(ctx)

	l.uc.SetUpgrader(nil)
	return err
}

// AgentInfo retrieves agent information.
func (l *Local) AgentInfo() *info.AgentInfo {
	return l.agentInfo
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
