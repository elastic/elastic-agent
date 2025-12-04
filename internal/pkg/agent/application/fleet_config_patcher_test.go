// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package application

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func Test_FleetPatcher(t *testing.T) {
	configFile := filepath.Join(".", "coordinator", "testdata", "overrides.yml")

	testCases := []struct {
		name               string
		isManaged          bool
		featureEnable      bool
		expectedLogs       bool
		expectedOutputType string
	}{
		{name: "managed - enabled", isManaged: true, featureEnable: true, expectedLogs: false, expectedOutputType: "kafka"},
		{name: "managed - disabled", isManaged: true, featureEnable: false, expectedLogs: true, expectedOutputType: "elasticsearch"},
		{name: "not managed - enabled", isManaged: false, featureEnable: true, expectedLogs: true, expectedOutputType: "elasticsearch"},
		{name: "not managed - disabled", isManaged: false, featureEnable: false, expectedLogs: true, expectedOutputType: "elasticsearch"},
	}

	overridesFile, err := os.OpenFile(configFile, os.O_RDONLY, 0)
	require.NoError(t, err)
	defer overridesFile.Close()

	rawConfig, err := config.NewConfigFrom(overridesFile)
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			caps := &mockCapabilities{}
			caps.On("AllowFleetOverride").Return(tc.featureEnable)

			log, _ := loggertest.New(t.Name())

			cfg, err := config.LoadFile(filepath.Join(".", "coordinator", "testdata", "config.yaml"))
			require.NoError(t, err)

			configChange := &mockConfigChange{
				c: cfg,
			}

			patcher := PatchFleetConfig(log, rawConfig, caps, tc.isManaged)
			patcher(configChange)

			c := &configuration.Configuration{}
			require.NoError(t, cfg.Agent.Unpack(&c))
			assert.Equal(t, tc.expectedLogs, c.Settings.MonitoringConfig.MonitorLogs)
			require.True(t, c.Settings.MonitoringConfig.MonitorMetrics)
			require.True(t, c.Settings.MonitoringConfig.Enabled)

			// make sure output is not kafka
			oc, err := cfg.Agent.Child("outputs", -1)
			require.NoError(t, err)

			do, err := oc.Child("default", -1)
			require.NoError(t, err)

			outputType, err := do.String("type", -1)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedOutputType, outputType, "output type should be %s, got %s", tc.expectedOutputType, outputType)
		})
	}
}

type mockCapabilities struct {
	mock.Mock
}

func (m *mockCapabilities) AllowUpgrade(version string, sourceURI string) bool {
	args := m.Called(version, sourceURI)
	return args.Bool(0)
}

func (m *mockCapabilities) AllowInput(name string) bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockCapabilities) AllowOutput(name string) bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *mockCapabilities) AllowFleetOverride() bool {
	args := m.Called()
	return args.Bool(0)
}
