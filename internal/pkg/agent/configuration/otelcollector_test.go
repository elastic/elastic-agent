// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCollectorConfig_Validate(t *testing.T) {
	testCases := []struct {
		name        string
		endpoint    string
		expectError bool
	}{
		{
			name:        "Valid endpoint",
			endpoint:    "http://localhost:13133",
			expectError: false,
		},
		{
			name:        "Empty endpoint",
			endpoint:    "",
			expectError: false,
		},
		{
			name:        "Invalid scheme",
			endpoint:    "https://localhost:13133",
			expectError: true,
		},
		{
			name:        "Missing port",
			endpoint:    "http://localhost",
			expectError: true,
		},
		{
			name:        "invalid endpoint",
			endpoint:    "npipe:/tmp",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hcConfig := &CollectorHealthCheckConfig{Endpoint: tc.endpoint}
			err := hcConfig.Validate()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			telConfig := &CollectorTelemetryConfig{Endpoint: tc.endpoint}
			err = telConfig.Validate()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCollectorHealthCheckConfig_Port(t *testing.T) {
	config := &CollectorHealthCheckConfig{Endpoint: "http://localhost:13133"}
	port, err := config.Port()
	assert.NoError(t, err)
	assert.Equal(t, 13133, port)
}

func TestCollectorTelemetryConfig_Port(t *testing.T) {
	config := &CollectorTelemetryConfig{Endpoint: "http://localhost:8888"}
	port, err := config.Port()
	assert.NoError(t, err)
	assert.Equal(t, 8888, port)
}

func TestDefaultCollectorConfig(t *testing.T) {
	defaultConfig := DefaultCollectorConfig()
	assert.NotNil(t, defaultConfig)
	assert.Equal(t, CollectorHealthCheckConfig{}, defaultConfig.HealthCheckConfig)
	assert.Equal(t, CollectorTelemetryConfig{}, defaultConfig.TelemetryConfig)
}
