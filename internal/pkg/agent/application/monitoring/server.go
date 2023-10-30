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

	"github.com/gorilla/mux"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgorilla"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

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
) (*reload.ServerReloader, error) {
	if err := createAgentMonitoringDrop(endpointConfig.Host); err != nil {
		// log but ignore
		log.Warnf("failed to create monitoring drop: %v", err)
	}

	if strings.TrimSpace(endpointConfig.Host) == "" {
		endpointConfig.Host = monitoringCfg.DefaultHost
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
) (*reload.ServerReloader, error) {
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

	newServerFn := func() (reload.ServerController, error) {
		apiServer, err := api.New(log, mux, config)
		if err != nil {
			return nil, errors.New(err, "failed to create api server")
		}
		return apiServer, nil
	}

	return reload.NewServerReloader(newServerFn, log, mcfg), nil
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
