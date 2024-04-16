// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package reload

import (
	"sync/atomic"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	aConfig "github.com/elastic/elastic-agent/internal/pkg/config"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ServerController controls the server runtime
type ServerController interface {
	Start()
	Stop() error
}
type serverConstructor func() (ServerController, error)

type ServerReloader struct {
	s           ServerController
	log         *logger.Logger
	newServerFn serverConstructor

	config          *monitoringCfg.MonitoringConfig
	isServerRunning atomic.Bool
}

func NewServerReloader(newServerFn serverConstructor, log *logger.Logger, mcfg *monitoringCfg.MonitoringConfig) *ServerReloader {
	sr := &ServerReloader{
		log:         log,
		config:      mcfg,
		newServerFn: newServerFn,
	}

	return sr
}

func (sr *ServerReloader) Start() {
	if sr.s != nil && sr.isServerRunning.Load() {
		// server is already running
		return
	}

	sr.log.Info("Starting server")
	var err error
	sr.s, err = sr.newServerFn()
	if err != nil {
		sr.log.Errorf("Failed creating a server: %v", err)
		return
	}

	sr.s.Start()
	sr.log.Debugf("Server started")
	sr.isServerRunning.Store(true)
}

func (sr *ServerReloader) Stop() error {
	if sr.s == nil {
		// stopping not started server
		sr.isServerRunning.Store(false)
		return nil
	}
	sr.log.Info("Stopping server")

	sr.isServerRunning.Store(false)
	if err := sr.s.Stop(); err != nil {
		return err
	}

	sr.log.Debugf("Server stopped")
	sr.s = nil
	return nil
}

func (sr *ServerReloader) Reload(rawConfig *aConfig.Config) error {
	newConfig := configuration.DefaultConfiguration()
	if err := rawConfig.Unpack(&newConfig); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}

	sr.config = newConfig.Settings.MonitoringConfig

	shouldRunMetrics := sr.config.Enabled
	if shouldRunMetrics && !sr.isServerRunning.Load() {
		sr.Start()

		sr.isServerRunning.Store(true)
		return nil
	}

	if !shouldRunMetrics && sr.isServerRunning.Load() {
		sr.isServerRunning.Store(false)
		return sr.Stop()
	}

	return nil
}
