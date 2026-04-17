// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package monitoring

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/gorilla/mux"

	"github.com/elastic/elastic-agent-libs/api"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/elastic-agent-system-metrics/report"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

// EDOTComponentID is the component ID for the EDOT collector.
const EDOTComponentID = "elastic-otel-collector"

// EDOTMonitoringEndpoint returns the monitoring endpoint for the EDOT collector.
func EDOTMonitoringEndpoint() string {
	return utils.SocketURLWithFallback(EDOTComponentID, paths.TempDir())
}

// NewServer creates a new server exposing metrics and process information.
func NewServer(log *logp.Logger, host string) (*api.Server, error) {
	ephemeralID, err := generateEphemeralID()
	if err != nil {
		return nil, err
	}

	if err := report.SetupMetricsOptions(report.MetricOptions{
		Name:           EDOTComponentID,
		Version:        version.GetDefaultVersion(),
		Logger:         log,
		EphemeralID:    ephemeralID,
		SystemMetrics:  monitoring.Default.GetOrCreateRegistry("system"),
		ProcessMetrics: monitoring.Default.GetOrCreateRegistry("beat"),
	}); err != nil {
		return nil, fmt.Errorf("failed to setup metrics: %w", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		data := monitoring.CollectStructSnapshot(
			monitoring.GetNamespace("stats").GetRegistry(),
			monitoring.Full,
			false,
		)

		bytes, err := json.Marshal(data)
		var content string
		if err != nil {
			content = fmt.Sprintf("Not valid json: %v", err)
		} else {
			content = string(bytes)
		}
		fmt.Fprint(w, content)
	})

	mux := http.NewServeMux()
	mux.Handle("/", r)

	err = createMonitoringPath(host)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitoring path: %w", err)
	}

	srvCfg := api.DefaultConfig()
	srvCfg.Enabled = true
	srvCfg.Host = host
	srvCfg.Port = 0
	apiServer, err := api.NewFromConfig(log, mux, srvCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create api server: %w", err)
	}
	return apiServer, nil
}

// createMonitoringPath checks and creates the drop path if it doesn't exist.
func createMonitoringPath(drop string) error {
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

// isHttpUrl checks if the given string is a valid HTTP URL.
func isHttpUrl(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// generateEphemeralID generates a random UUID.
func generateEphemeralID() (string, error) {
	uid, err := uuid.NewV4()
	if err != nil {
		return "", fmt.Errorf("error while generating UUID for agent: %w", err)
	}

	return uid.String(), nil
}
