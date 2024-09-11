// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	// the state of HTTP.Enabled when we call NewServerReloader
	originalHTTPState *monitoringCfg.MonitoringHTTPConfig
}

func NewServerReloader(newServerFn serverConstructor, log *logger.Logger, mcfg *monitoringCfg.MonitoringConfig) *ServerReloader {
	sr := &ServerReloader{
		log:               log,
		config:            mcfg,
		newServerFn:       newServerFn,
		originalHTTPState: mcfg.HTTP,
	}
	return sr
}

func (sr *ServerReloader) Start() {
	if sr.srvController != nil && sr.isServerRunning.Load() {
		// server is already running
		return
	}

	sr.log.Infof("Starting monitoring server with cfg %#v", sr.config)
	var err error
	sr.srvController, err = sr.newServerFn(sr.config)
	if err != nil {
		sr.log.Errorf("Failed creating a server: %v", err)
		return
	}

	sr.srvController.Start()
	sr.log.Debugf("Monitoring server started")
	sr.isServerRunning.Store(true)

}

func (sr *ServerReloader) Stop() error {
	if sr.srvController == nil {
		// stopping not started server
		sr.isServerRunning.Store(false)
		return nil
	}
	sr.log.Info("Stopping monitoring server")

	sr.isServerRunning.Store(false)
	if err := sr.srvController.Stop(); err != nil {
		return err
	}

	sr.log.Debugf("Monitoring server stopped")
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
	// If it was set in the original init config (which includes overrides), and it wasn't explicitly disabled
	// then pretend the HTTP monitoring is enabled
	if sr.originalHTTPState != nil && sr.originalHTTPState.Enabled &&
		newConfig.Settings.MonitoringConfig != nil && !newConfig.Settings.MonitoringConfig.HTTP.EnabledIsSet {
		sr.log.Infof("http monitoring server is enabled in hard-coded config, but HTTP config is unset. Leaving enabled.")
		newConfig.Settings.MonitoringConfig.HTTP = sr.originalHTTPState
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
