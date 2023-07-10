// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/utils"
)

const (
	componentIDKey         = "componentID"
	metricsPathKey         = "metricsPath"
	timeout                = 10 * time.Second
	apmPrefix              = "apm-server"
	apmTypePrefix          = "apm"
	fleetServerPrefix      = "fleet-server"
	profilingServicePrefix = "pf-elastic-"
)

var redirectPathAllowlist = map[string]struct{}{
	"":      {},
	"stats": {},
	"state": {},
}

var redirectableProcesses = []string{
	apmTypePrefix,
	fleetServerPrefix,
	profilingServicePrefix,
}

func processHandler(coord *coordinator.Coordinator, statsHandler func(http.ResponseWriter, *http.Request) error, operatingSystem string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		vars := mux.Vars(r)

		componentID, found := vars[componentIDKey]
		if !found {
			return errorfWithStatus(http.StatusNotFound, "process with specified ID not found")
		}

		if componentID == "" || componentID == paths.BinaryName {
			// proxy stats for elastic agent process
			return statsHandler(w, r)
		}

		componentID = cloudComponentIDToAgentInputType(componentID)

		if isProcessRedirectable(componentID) {
			// special handling for redirectable processes
			// apm needs its own output even for no path
			metricsPath := vars[metricsPathKey]
			_, ok := redirectPathAllowlist[metricsPath]
			if !ok {
				return errorfWithStatus(http.StatusNotFound, "process specified does not expose metrics")
			}

			if strings.HasPrefix(componentID, fleetServerPrefix) && metricsPathKey == "" {
				// special case, fleet server is expected to return stats right away
				// removing this would be breaking
				metricsPath = "stats"
			}

			return redirectToPath(w, r, componentID, metricsPath, operatingSystem)
		}

		state := coord.State()

		for _, c := range state.Components {
			if matchesCloudProcessID(&c.Component, componentID) {
				data := struct {
					State   string `json:"state"`
					Message string `json:"message"`
				}{
					State:   c.State.State.String(),
					Message: c.State.Message,
				}

				bytes, err := json.Marshal(data)
				var content string
				if err != nil {
					content = fmt.Sprintf("Not valid json: %v", err)
				} else {
					content = string(bytes)
				}
				fmt.Fprint(w, content)

				return nil
			}
		}

		return errorWithStatus(http.StatusNotFound, fmt.Errorf("matching component %v not found", componentID))
	}
}

func isProcessRedirectable(componentID string) bool {
	processNameLower := strings.ToLower(componentID)
	for _, prefix := range redirectableProcesses {
		if strings.HasPrefix(processNameLower, prefix) {
			return true
		}
	}
	return false
}

func redirectToPath(w http.ResponseWriter, r *http.Request, id, path, operatingSystem string) error {
	endpoint := prefixedEndpoint(utils.SocketURLWithFallback(id, paths.TempDir()))
	metricsBytes, statusCode, metricsErr := processMetrics(r.Context(), endpoint, path)
	if metricsErr != nil {
		return metricsErr
	}

	if statusCode > 0 {
		w.WriteHeader(statusCode)
	}

	fmt.Fprint(w, string(metricsBytes))
	return nil
}

func processMetrics(ctx context.Context, endpoint, path string) ([]byte, int, error) {
	hostData, err := parseURL(endpoint, "http", "", "", path, "")
	if err != nil {
		return nil, 0, errorWithStatus(http.StatusInternalServerError, err)
	}

	dialer, err := hostData.transport.Make(timeout)
	if err != nil {
		return nil, 0, errorWithStatus(http.StatusInternalServerError, err)
	}

	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}

	req, err := http.NewRequest(http.MethodGet, hostData.uri, nil)
	if err != nil {
		return nil, 0, errorWithStatus(
			http.StatusInternalServerError,
			fmt.Errorf("fetching metrics failed: %w", err),
		)
	}

	req.Close = true
	cctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	resp, err := client.Do(req.WithContext(cctx))
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, syscall.ENOENT) {
			statusCode = http.StatusNotFound
		}
		return nil, 0, errorWithStatus(statusCode, err)
	}
	defer resp.Body.Close()

	rb, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, errorWithStatus(http.StatusInternalServerError, err)
	}

	return rb, resp.StatusCode, nil
}
