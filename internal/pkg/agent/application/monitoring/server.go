// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgorilla"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"

	aConfig "github.com/elastic/elastic-agent/internal/pkg/config"
)

type serverConstructor func() (*api.Server, error)
type ServerReloader struct {
	s           *api.Server
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

	shouldRunMetrics := sr.config.Enabled && sr.config.MonitorMetrics
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

// New creates a new server exposing metrics and process information.
func NewServer(
	log *logger.Logger,
	endpointConfig api.Config,
	ns func(string) *monitoring.Namespace,
	tracer *apm.Tracer,
	coord *coordinator.Coordinator,
	enableProcessStats bool,
	operatingSystem string,
	mcfg *monitoringCfg.MonitoringConfig,
) (*ServerReloader, error) {
	if err := createAgentMonitoringDrop(endpointConfig.Host); err != nil {
		// log but ignore
		log.Errorf("failed to create monitoring drop: %v", err)
	}

	cfg, err := config.NewConfigFrom(endpointConfig)
	if err != nil {
		return nil, err
	}

	return exposeMetricsEndpoint(log, cfg, ns, tracer, coord, enableProcessStats, operatingSystem, mcfg)
}

func exposeMetricsEndpoint(
	log *logger.Logger,
	config *config.C,
	ns func(string) *monitoring.Namespace,
	tracer *apm.Tracer,
	coord *coordinator.Coordinator,
	enableProcessStats bool,
	operatingSystem string,
	mcfg *monitoringCfg.MonitoringConfig,
) (*ServerReloader, error) {
	r := mux.NewRouter()
	if tracer != nil {
		r.Use(apmgorilla.Middleware(apmgorilla.WithTracer(tracer)))
	}
	statsHandler := statsHandler(ns("stats"))
	r.Handle("/stats", createHandler(statsHandler))

	if enableProcessStats {
		r.Handle("/processes", createHandler(processesHandler(coord)))
		r.Handle("/processes/{componentID}", createHandler(processHandler(coord, statsHandler, operatingSystem)))
		r.Handle("/processes/{componentID}/", createHandler(processHandler(coord, statsHandler, operatingSystem)))
		r.Handle("/processes/{componentID}/{metricsPath}", createHandler(processHandler(coord, statsHandler, operatingSystem)))
	}

	mux := http.NewServeMux()
	mux.Handle("/", r)

	newServerFn := func() (*api.Server, error) {
		apiServer, err := api.New(log, mux, config)
		if err != nil {
			return nil, errors.New(err, "failed to create api server")
		}
		return apiServer, nil
	}

	return NewServerReloader(newServerFn, log, mcfg), nil
}

func createAgentMonitoringDrop(drop string) error {
	if drop == "" || runtime.GOOS == "windows" || isHttpUrl(drop) {
		return nil
	}

	path := strings.TrimPrefix(drop, "unix://")
	if strings.HasSuffix(path, ".sock") {
		path = filepath.Dir(path)
	}

	_, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}

		// create
		if err := os.MkdirAll(path, 0775); err != nil {
			return err
		}
	}

	return os.Chown(path, os.Geteuid(), os.Getegid())
}

func isHttpUrl(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
