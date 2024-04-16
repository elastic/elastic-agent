// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package reload

import (
	"fmt"
	"net"
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
	Addr() net.Addr
}
type serverConstructor func(*monitoringCfg.MonitoringConfig) (ServerController, error)

type ServerReloader struct {
	srvController ServerController
	log           *logger.Logger
	newServerFn   serverConstructor

	config          *monitoringCfg.MonitoringConfig
	isServerRunning atomic.Bool
	// is set based on the value of MonitoringConfig.HTTP.Enabled
	httpIsRunning atomic.Bool
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
	if sr.srvController != nil && sr.isServerRunning.Load() {
		// server is already running
		return
	}

	sr.log.Info("Starting server")
	var err error
	sr.srvController, err = sr.newServerFn(sr.config)
	if err != nil {
		sr.log.Errorf("Failed creating a server: %v", err)
		return
	}

	sr.srvController.Start()
	sr.log.Debugf("Server started")
	sr.isServerRunning.Store(true)
	if sr.config.HTTP != nil && sr.config.HTTP.Enabled {
		sr.httpIsRunning.Store(true)
	}
}

func (sr *ServerReloader) Stop() error {
	if sr.srvController == nil {
		// stopping not started server
		sr.isServerRunning.Store(false)
		return nil
	}
	sr.log.Info("Stopping server")

	sr.isServerRunning.Store(false)
	if err := sr.srvController.Stop(); err != nil {
		return err
	}

	sr.httpIsRunning.Store(false)

	sr.log.Debugf("Server stopped")
	sr.srvController = nil
	return nil
}

// Addr returns the address interface used by the underlying network listener
func (sr *ServerReloader) Addr() net.Addr {
	if sr.srvController != nil {
		return sr.srvController.Addr()
	}
	// just return a "bare" Addr so we don't have to return a nil
	return &net.TCPAddr{Port: 0, IP: net.IP{}}
}

func (sr *ServerReloader) Reload(rawConfig *aConfig.Config) error {
	newConfig := configuration.DefaultConfiguration()
	if err := rawConfig.Unpack(&newConfig); err != nil {
		return errors.New(err, "failed to unpack monitoring config during reload")
	}

	// see https://github.com/elastic/elastic-agent/issues/4582
	// currently, fleet does not expect the monitoring to be reloadable.
	// If it's currently running and the monitoring.http.enabled value hasn't been set,
	// then pretend the HTTP monitoring is enabled
	if sr.httpIsRunning.Load() && !newConfig.Settings.MonitoringConfig.HTTP.EnabledIsSet {
		newConfig.Settings.MonitoringConfig.HTTP.Enabled = true
	}

	sr.config = newConfig.Settings.MonitoringConfig
	var err error

	if sr.config != nil && sr.config.Enabled {
		if sr.isServerRunning.Load() {
			err = sr.Stop()
			if err != nil {
				return fmt.Errorf("error stopping monitoring server: %w", err)
			}
		}

		sr.Start()

		return nil
	}

	if sr.config != nil && !sr.config.Enabled && sr.isServerRunning.Load() {

		return sr.Stop()
	}

	return nil
}
