// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package application

import (
	"context"
	"fmt"

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
	"github.com/elastic/elastic-agent/internal/pkg/core/logger"
)

// Application is the application interface implemented by the different running mode.
type Application interface {
	Start() error
	Stop() error
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
func New(log *logger.Logger, reexec reexecManager, statusCtrl status.Controller, uc upgraderControl, agentInfo *info.AgentInfo) (Application, error) {
	// Load configuration from disk to understand in which mode of operation
	// we must start the elastic-agent, the mode of operation cannot be changed without restarting the
	// elastic-agent.
	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return nil, err
	}

	if err := info.InjectAgentConfig(rawConfig); err != nil {
		return nil, err
	}

	return createApplication(log, pathConfigFile, rawConfig, reexec, statusCtrl, uc, agentInfo)
}

func createApplication(
	log *logger.Logger,
	pathConfigFile string,
	rawConfig *config.Config,
	reexec reexecManager,
	statusCtrl status.Controller,
	uc upgraderControl,
	agentInfo *info.AgentInfo,
) (Application, error) {
	log.Info("Detecting execution mode")
	ctx := context.Background()
	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	if configuration.IsStandalone(cfg.Fleet) {
		log.Info("Agent is managed locally")
		return newLocal(ctx, log, paths.ConfigFile(), rawConfig, reexec, statusCtrl, uc, agentInfo)
	}

	// not in standalone; both modes require reading the fleet.yml configuration file
	var store storage.Store
	store, cfg, err = mergeFleetConfig(rawConfig)
	if err != nil {
		return nil, err
	}

	if configuration.IsFleetServerBootstrap(cfg.Fleet) {
		log.Info("Agent is in Fleet Server bootstrap mode")
		return newFleetServerBootstrap(ctx, log, pathConfigFile, rawConfig, statusCtrl, agentInfo)
	}

	log.Info("Agent is managed by Fleet")
	return newManaged(ctx, log, store, cfg, rawConfig, reexec, statusCtrl, agentInfo)
}

func mergeFleetConfig(rawConfig *config.Config) (storage.Store, *configuration.Configuration, error) {
	path := paths.AgentConfigFile()
	store := storage.NewDiskStore(path)
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
