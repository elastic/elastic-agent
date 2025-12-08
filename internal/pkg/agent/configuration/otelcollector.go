// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"fmt"
	"net/url"
	"strconv"
)

type CollectorConfig struct {
	HealthCheckConfig CollectorHealthCheckConfig `yaml:"healthcheck" config:"healthcheck" json:"healthcheck"`
	TelemetryConfig   CollectorTelemetryConfig   `yaml:"telemetry" config:"telemetry" json:"telemetry"`
}

type CollectorHealthCheckConfig struct {
	Endpoint string `yaml:"endpoint" config:"endpoint" json:"endpoint"`
}

func (c *CollectorHealthCheckConfig) Validate() error {
	return validateEndpoint(c.Endpoint)
}

func (c *CollectorHealthCheckConfig) Port() (int, error) {
	return getPort(c.Endpoint)
}

type CollectorTelemetryConfig struct {
	Endpoint string `yaml:"endpoint" config:"endpoint" json:"endpoint"`
}

func (c *CollectorTelemetryConfig) Validate() error {
	return validateEndpoint(c.Endpoint)
}

func (c *CollectorTelemetryConfig) Port() (int, error) {
	return getPort(c.Endpoint)
}

func DefaultCollectorConfig() *CollectorConfig {
	return &CollectorConfig{
		HealthCheckConfig: CollectorHealthCheckConfig{},
		TelemetryConfig:   CollectorTelemetryConfig{},
	}
}

func validateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" { // the otel metrics prometheus exporter only supports http right now
		return fmt.Errorf("invalid endpoint '%s': must use http", endpoint)
	}

	if parsed.Port() == "" {
		return fmt.Errorf("invalid endpoint '%s': port must be specified", endpoint)
	}

	return nil
}

func getPort(endpoint string) (int, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(parsed.Port())
}
