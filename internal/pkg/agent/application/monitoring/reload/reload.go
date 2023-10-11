// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package reload

import (
	"sync"

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

	config              *monitoringCfg.MonitoringConfig
	isServerRunning     bool
	isServerRunningLock sync.Mutex
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
	sr.isServerRunningLock.Lock()
	defer sr.isServerRunningLock.Unlock()

	sr.start()
}

func (sr *ServerReloader) start() {
	if sr.s != nil && sr.isServerRunning {
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
	sr.isServerRunning = true
}

func (sr *ServerReloader) Stop() error {
	sr.isServerRunningLock.Lock()
	defer sr.isServerRunningLock.Unlock()

	return sr.stop()
}

func (sr *ServerReloader) stop() error {
	if sr.s == nil {
		// stopping not started server
		sr.isServerRunning = false
		return nil
	}
	sr.log.Info("Stopping server")

	sr.isServerRunning = false
	if err := sr.s.Stop(); err != nil {
		return err
	}

	sr.log.Debugf("Server stopped")
	sr.s = nil
	return nil
}

func (sr *ServerReloader) Reload(rawConfig *aConfig.Config) error {
	sr.isServerRunningLock.Lock()
	defer sr.isServerRunningLock.Unlock()

	newConfig := configuration.DefaultConfiguration()
	if err := rawConfig.Unpack(&newConfig); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}

	sr.config = newConfig.Settings.MonitoringConfig

	shouldRunMetrics := sr.config.Enabled
	if shouldRunMetrics && !sr.isServerRunning {
		sr.start()

		sr.isServerRunning = true
		return nil
	}

	if !shouldRunMetrics && sr.isServerRunning {
		sr.isServerRunning = false
		return sr.stop()
	}

	return nil
}
