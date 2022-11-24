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
)

const (
	processIDKey = "processID"
	timeout      = 10 * time.Second
)

var redirectPathAllowlist = map[string]struct{}{
	"stats": {},
	"state": {},
}

var redirectableProcesses = []string{
	"apm-server",
	"fleet-server",
}

func processHandler(coord *coordinator.Coordinator, statsHandler func(http.ResponseWriter, *http.Request) error, operatingSystem string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		vars := mux.Vars(r)

		id, found := vars[processIDKey]
		if !found {
			return errorfWithStatus(http.StatusNotFound, "productID not found")
		}

		if id == "" || id == paths.BinaryName {
			// proxy stats for elastic agent process
			return statsHandler(w, r)
		}

		metricsPath := vars["metricsPath"]
		if _, ok := redirectPathAllowlist[metricsPath]; ok {
			if isProcessRedirectable(id) {
				return redirectToPath(w, r, id, metricsPath, operatingSystem)
			}
			return errorfWithStatus(http.StatusNotFound, "endpoint not found")
		}

		state := coord.State(false)

		for _, c := range state.Components {
			if c.Component.ID == id {
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

		return errorWithStatus(http.StatusNotFound, fmt.Errorf("matching component %v not found", id))
	}
}

func isProcessRedirectable(processName string) bool {
	processNameLower := strings.ToLower(processName)
	for _, prefix := range redirectableProcesses {
		if strings.HasPrefix(processNameLower, prefix) {
			return true
		}
	}
	return false
}

func redirectToPath(w http.ResponseWriter, r *http.Request, id, path, operatingSystem string) error {
	endpoint := prefixedEndpoint(endpointPath(id, operatingSystem))
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

	req, err := http.NewRequest("GET", hostData.uri, nil)
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
