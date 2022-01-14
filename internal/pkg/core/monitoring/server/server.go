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

package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gorilla/mux"

	"github.com/elastic/beats/v7/libbeat/api"
	"github.com/elastic/beats/v7/libbeat/common"
	"github.com/elastic/beats/v7/libbeat/monitoring"
	"github.com/elastic/elastic-agent-poc/internal/pkg/core/logger"
	"github.com/elastic/elastic-agent-poc/internal/pkg/sorted"
)

// New creates a new server exposing metrics and process information.
func New(
	log *logger.Logger,
	endpointConfig api.Config,
	ns func(string) *monitoring.Namespace,
	routesFetchFn func() *sorted.Set,
	enableProcessStats bool,
) (*api.Server, error) {
	if err := createAgentMonitoringDrop(endpointConfig.Host); err != nil {
		// log but ignore
		log.Errorf("failed to create monitoring drop: %v", err)
	}

	cfg, err := common.NewConfigFrom(endpointConfig)
	if err != nil {
		return nil, err
	}

	return exposeMetricsEndpoint(log, cfg, ns, routesFetchFn, enableProcessStats)
}

func exposeMetricsEndpoint(log *logger.Logger, config *common.Config, ns func(string) *monitoring.Namespace, routesFetchFn func() *sorted.Set, enableProcessStats bool) (*api.Server, error) {
	r := mux.NewRouter()
	statsHandler := statsHandler(ns("stats"))
	r.Handle("/stats", createHandler(statsHandler))

	if enableProcessStats {
		r.HandleFunc("/processes", processesHandler(routesFetchFn))
		r.Handle("/processes/{processID}", createHandler(processHandler(statsHandler)))
		r.Handle("/processes/{processID}/", createHandler(processHandler(statsHandler)))
		r.Handle("/processes/{processID}/{beatsPath}", createHandler(processHandler(statsHandler)))
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
