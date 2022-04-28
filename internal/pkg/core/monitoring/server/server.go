// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"fmt"
	"net/http"
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
	"github.com/elastic/elastic-agent-libs/monitoring/report/buffer"
	"github.com/elastic/elastic-agent/internal/pkg/sorted"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// New creates a new server exposing metrics and process information.
func New(
	log *logger.Logger,
	endpointConfig api.Config,
	ns func(string) *monitoring.Namespace,
	routesFetchFn func() *sorted.Set,
	enableProcessStats bool,
	enableBuffer bool,
	tracer *apm.Tracer,
) (*api.Server, error) {
	if err := createAgentMonitoringDrop(endpointConfig.Host); err != nil {
		// log but ignore
		log.Errorf("failed to create monitoring drop: %v", err)
	}

	cfg, err := config.NewConfigFrom(endpointConfig)
	if err != nil {
		return nil, err
	}

	return exposeMetricsEndpoint(log, cfg, ns, routesFetchFn, enableProcessStats, enableBuffer, tracer)
}

func exposeMetricsEndpoint(
	log *logger.Logger,
	config *config.C,
	ns func(string) *monitoring.Namespace,
	routesFetchFn func() *sorted.Set,
	enableProcessStats bool,
	enableBuffer bool,
	tracer *apm.Tracer,
) (*api.Server, error) {
	r := mux.NewRouter()
	if tracer != nil {
		r.Use(apmgorilla.Middleware(apmgorilla.WithTracer(tracer)))
	}
	statsHandler := statsHandler(ns("stats"))
	r.Handle("/stats", createHandler(statsHandler))

	if enableProcessStats {
		r.HandleFunc("/processes", processesHandler(routesFetchFn))
		r.Handle("/processes/{processID}", createHandler(processHandler(statsHandler)))
		r.Handle("/processes/{processID}/", createHandler(processHandler(statsHandler)))
		r.Handle("/processes/{processID}/{beatsPath}", createHandler(processHandler(statsHandler)))
	}

	if enableBuffer {
		bufferReporter, err := buffer.MakeReporter(config) // beat.Info is not used by buffer reporter
		if err != nil {
			return nil, fmt.Errorf("unable to create buffer reporter for elastic-agent: %w", err)
		}
		r.Handle("/buffer", bufferReporter)
	}

	mux := http.NewServeMux()
	mux.Handle("/", r)

	return api.New(log, mux, config)
}

func createAgentMonitoringDrop(drop string) error {
	if drop == "" || runtime.GOOS == "windows" {
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

func errorWithStatus(status int, err error) *statusError {
	return &statusError{
		err:    err,
		status: status,
	}
}

func errorfWithStatus(status int, msg string, args ...string) *statusError {
	err := fmt.Errorf(msg, args)
	return errorWithStatus(status, err)
}

// StatusError holds correlation between error and a status
type statusError struct {
	err    error
	status int
}

func (s *statusError) Status() int {
	return s.status
}

func (s *statusError) Error() string {
	return s.err.Error()
}
