// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/internal/pkg/otel/status"

	otelstatus "github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
)

const (
	// healthcheckv2 extension configuration settings
	// https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckv2extension
	healthCheckExtensionName            = "healthcheckv2"
	healthCheckIncludePermanentErrors   = true
	healthCheckIncludeRecoverableErrors = true
	healthCheckRecoveryDuration         = "5m"
	healthCheckHealthStatusPath         = "/health/status"
	healthCheckHealthStatusEnabled      = true
	healthCheckHealthConfigPath         = "/health/config"
	healthCheckHealthConfigEnabled      = false
)

// AllComponentsStatuses retrieves the status of all components from the health check endpoint.
func AllComponentsStatuses(ctx context.Context, httpHealthCheckPort int) (*otelstatus.AggregateStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://localhost:%d/%s?verbose",
		httpHealthCheckPort, healthCheckHealthStatusPath), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	serStatus := &status.SerializableStatus{}
	err = json.Unmarshal(body, serStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal serializable status: %w", err)
	}

	return status.FromSerializableStatus(serStatus)
}

// injectHealthCheckV2Extension injects the healthcheckv2 extension into the provided configuration.
func injectHealthCheckV2Extension(conf *confmap.Conf, healthCheckExtensionID string, httpHealthCheckPort int) error {
	err := conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"extensions": map[string]interface{}{
			healthCheckExtensionID: map[string]interface{}{
				"use_v2": true,
				"component_health": map[string]interface{}{
					"include_permanent_errors":   healthCheckIncludePermanentErrors,
					"include_recoverable_errors": healthCheckIncludeRecoverableErrors,
					"recovery_duration":          healthCheckRecoveryDuration,
				},
				"http": map[string]interface{}{
					"endpoint": fmt.Sprintf("localhost:%d", httpHealthCheckPort),
					"status": map[string]interface{}{
						"enabled":            healthCheckHealthStatusEnabled,
						"path":               healthCheckHealthStatusPath,
						"include_attributes": true,
					},
					"config": map[string]interface{}{
						"enabled": healthCheckHealthConfigEnabled,
						"path":    healthCheckHealthConfigPath,
					},
				},
			},
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into extensions failed: %w", err)
	}
	serviceConf, err := conf.Sub("service")
	if err != nil {
		//nolint:nilerr // ignore the error, no service defined in the configuration
		// this is going to error by the collector any way no reason to pollute with more
		// error information that is not really related to the issue at the moment
		return nil
	}
	extensionsRaw := serviceConf.Get("extensions")
	if extensionsRaw == nil {
		// no extensions defined on service (easily add it)
		err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
			"service": map[string]interface{}{
				"extensions": []interface{}{healthCheckExtensionID},
			},
		}))
		if err != nil {
			return fmt.Errorf("merge into service::extensions failed: %w", err)
		}
		return nil
	}
	extensionsSlice, ok := extensionsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("merge into service::extensions failed: expected []interface{}, got %T", extensionsRaw)
	}
	for _, extensionRaw := range extensionsSlice {
		extension, ok := extensionRaw.(string)
		if ok && extension == healthCheckExtensionID {
			// already present, nothing to do
			return nil
		}
	}
	extensionsSlice = append(extensionsSlice, healthCheckExtensionID)
	err = conf.Merge(confmap.NewFromStringMap(map[string]interface{}{
		"service": map[string]interface{}{
			"extensions": extensionsSlice,
		},
	}))
	if err != nil {
		return fmt.Errorf("merge into service::extensions failed: %w", err)
	}
	return nil
}
