// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // this is only conditionally exposed
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gorilla/mux"
	"go.elastic.co/apm/module/apmgorilla/v2"
	"go.elastic.co/apm/v2"

	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/reload"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// NewServer creates a new server exposing metrics and process information.
func NewServer(
	log *logger.Logger,
	ns func(string) *monitoring.Namespace,
	tracer *apm.Tracer,
	coord CoordinatorState,
	mcfg *monitoringCfg.MonitoringConfig,
) (*reload.ServerReloader, error) {

	newServerFn := func(cfg *monitoringCfg.MonitoringConfig) (reload.ServerController, error) {
		r := mux.NewRouter()
		if tracer != nil {
			r.Use(apmgorilla.Middleware(apmgorilla.WithTracer(tracer)))
		}

		// This will probably only be nil in tests.
		statNs := &monitoring.Namespace{}
		if ns != nil {
			statNs = ns("stats")
		}

		statsHandler := statsHandler(statNs)
		r.Handle("/stats", createHandler(statsHandler))
		r.Handle("/readiness", createHandler(readinessHandler(coord)))
		r.Handle("/liveness", createHandler(livenessHandler(coord)))

		if isProcessStatsEnabled(cfg) {
			log.Infof("process monitoring is enabled, creating monitoring endpoints")
			r.Handle("/processes", createHandler(processesHandler(coord)))
			r.Handle("/processes/{componentID}", createHandler(processHandler(coord, statsHandler)))
			r.Handle("/processes/{componentID}/", createHandler(processHandler(coord, statsHandler)))
			r.Handle("/processes/{componentID}/{metricsPath}", createHandler(processHandler(coord, statsHandler)))
		}

		if isPprofEnabled(cfg) {
			// importing net/http/pprof adds the handlers to the right paths on the default Mux, so we just defer to it here
			r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
		}

		mux := http.NewServeMux()
		mux.Handle("/", r)

		if strings.TrimSpace(cfg.HTTP.Host) == "" {
			cfg.HTTP.Host = monitoringCfg.DefaultHost
		}

		srvCfg := api.DefaultConfig()
		srvCfg.Enabled = cfg.Enabled
		srvCfg.Host = componentmonitoring.AgentMonitoringEndpoint(cfg)
		srvCfg.Port = cfg.HTTP.Port
		log.Infof("creating monitoring API with cfg %#v", srvCfg)
		if err := createAgentMonitoringDrop(srvCfg.Host); err != nil {
			// if it cannot create the path for the socket, then we cannot start the server
			return nil, fmt.Errorf("failed to create monitoring socket directory: %w", err)
		}
		apiServer, err := api.NewFromConfig(log, mux, srvCfg)
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

func isProcessStatsEnabled(cfg *monitoringCfg.MonitoringConfig) bool {
	return cfg != nil && cfg.HTTP.Enabled
}

func isPprofEnabled(cfg *monitoringCfg.MonitoringConfig) bool {
	return cfg != nil && cfg.Pprof != nil && cfg.Pprof.Enabled
}
