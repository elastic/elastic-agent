// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	agentcomponent "github.com/elastic/elastic-agent/pkg/component"
)

func TestFindRandomPort(t *testing.T) {
	portCount := 2
	ports, err := findRandomTCPPorts(portCount)
	require.NoError(t, err)
	require.Len(t, ports, portCount)
	for _, port := range ports {
		assert.NotEqual(t, 0, port)
	}
	slices.Sort(ports)
	require.Len(t, slices.Compact(ports), portCount, "returned ports should be unique")

	defer func() {
		netListen = net.Listen
	}()

	netListen = func(string, string) (net.Listener, error) {
		return nil, errors.New("some error")
	}
	_, err = findRandomTCPPorts(portCount)
	assert.Error(t, err, "failed to find random port")
}

func testComponent(componentId string) agentcomponent.Component {
	fileStreamConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"paths": []any{
					filepath.Join(paths.TempDir(), "nonexistent.log"),
				},
			},
			map[string]any{
				"id": "test-2",
				"data_stream": map[string]any{
					"dataset": "generic-2",
				},
				"paths": []any{
					filepath.Join(paths.TempDir(), "nonexistent.log"),
				},
			},
		},
	}

	esOutputConfig := map[string]any{
		"type":             "elasticsearch",
		"hosts":            []any{"localhost:9200"},
		"username":         "elastic",
		"password":         "password",
		"preset":           "balanced",
		"queue.mem.events": 3200,
	}

	return agentcomponent.Component{
		ID:             componentId,
		RuntimeManager: agentcomponent.OtelRuntimeManager,
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		InputSpec: &agentcomponent.InputRuntimeSpec{
			BinaryName: "agentbeat",
			Spec: agentcomponent.InputSpec{
				Command: &agentcomponent.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []agentcomponent.Unit{
			{
				ID:     "filestream-unit",
				Type:   client.UnitTypeInput,
				Config: agentcomponent.MustExpectedConfig(fileStreamConfig),
			},
			{
				ID:     "filestream-default",
				Type:   client.UnitTypeOutput,
				Config: agentcomponent.MustExpectedConfig(esOutputConfig),
			},
		},
	}
}

func TestOtelConfigToStatus(t *testing.T) {
	tests := []struct {
		name           string
		config         map[string]any
		err            error
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus)
	}{
		{
			name: "unmarshal error - invalid config structure",
			config: map[string]any{
				"service": "invalid", // should be a map, not a string
			},
			err:           errors.New("some error"),
			expectError:   true,
			errorContains: "could not unmarshal config",
		},
		{
			name: "no pipelines defined - empty pipelines map",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{},
				},
			},
			err:           errors.New("some error"),
			expectError:   true,
			errorContains: "no pipelines defined",
		},
		{
			name: "no pipelines defined - missing pipelines key",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{},
			},
			err:           errors.New("some error"),
			expectError:   true,
			errorContains: "no pipelines defined",
		},
		{
			name: "generic error - no match on any component",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New("generic error that doesn't match any component"),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				// All components should have fatal error status
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
				// Check that components are present
				require.NotEmpty(t, result.ComponentStatusMap)
			},
		},
		{
			name: "specific error - matches receiver with 'for id:' pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"otlp": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"otlp"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`error for id: "otlp" in config`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				// The matched component should have fatal error, others should be starting
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "specific error - matches receiver with 'failed to start' pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"otlp": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"otlp"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "otlp" receiver: connection refused`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "specific error - matches exporter with 'for id:' pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"otlp": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"otlp"},
						},
					},
				},
			},
			err:         errors.New(`error for id: "otlp" in exporter`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "specific error - matches processor with 'failed to start' pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"processors": map[string]any{
					"batch": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers":  []string{"nop"},
							"processors": []string{"batch"},
							"exporters":  []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "batch" processor: invalid config`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "extensions with generic error",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"extensions": map[string]any{
					"health_check": map[string]any{},
				},
				"service": map[string]any{
					"extensions": []string{"health_check"},
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New("generic startup error"),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
				// Should have extension in the status map
				require.NotEmpty(t, result.ComponentStatusMap)
			},
		},
		{
			name: "extensions with specific error - matches extension",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"extensions": map[string]any{
					"health_check": map[string]any{},
				},
				"service": map[string]any{
					"extensions": []string{"health_check"},
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "health_check" extension: port in use`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "connector as receiver and exporter - generic error",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"connectors": map[string]any{
					"forward": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"forward"},
						},
						"metrics": map[string]any{
							"receivers": []string{"forward"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New("generic error"),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
				// Connector should appear in the status
				require.NotEmpty(t, result.ComponentStatusMap)
			},
		},
		{
			name: "connector with specific error - matches extra pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"connectors": map[string]any{
					"forward": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"forward"},
						},
						"metrics": map[string]any{
							"receivers": []string{"forward"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`connector "forward" used as exporter failed`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "multiple pipelines with same components",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"processors": map[string]any{
					"batch": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers":  []string{"nop"},
							"processors": []string{"batch"},
							"exporters":  []string{"nop"},
						},
						"metrics": map[string]any{
							"receivers":  []string{"nop"},
							"processors": []string{"batch"},
							"exporters":  []string{"nop"},
						},
						"logs": map[string]any{
							"receivers":  []string{"nop"},
							"processors": []string{"batch"},
							"exporters":  []string{"nop"},
						},
					},
				},
			},
			err:         errors.New("generic startup failure"),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
				// Should have multiple pipeline entries
				require.NotEmpty(t, result.ComponentStatusMap)
			},
		},
		{
			name: "multiple receivers exporters and processors with specific match",
			config: map[string]any{
				"receivers": map[string]any{
					"nop":    map[string]any{},
					"nop/2":  map[string]any{},
					"otlp":   map[string]any{},
					"otlp/2": map[string]any{},
				},
				"processors": map[string]any{
					"batch":   map[string]any{},
					"batch/2": map[string]any{},
				},
				"exporters": map[string]any{
					"nop":   map[string]any{},
					"nop/2": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers":  []string{"nop", "nop/2", "otlp", "otlp/2"},
							"processors": []string{"batch", "batch/2"},
							"exporters":  []string{"nop", "nop/2"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "otlp/2" receiver: connection error`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "connector used in multiple pipeline combinations",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"connectors": map[string]any{
					"forward": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"forward"},
						},
						"traces/2": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"forward"},
						},
						"metrics": map[string]any{
							"receivers": []string{"forward"},
							"exporters": []string{"nop"},
						},
						"metrics/2": map[string]any{
							"receivers": []string{"forward"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New("connector initialization failed"),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "extension with for id pattern match",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"extensions": map[string]any{
					"health_check": map[string]any{},
				},
				"service": map[string]any{
					"extensions": []string{"health_check"},
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`error for id: "health_check" in extension config`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "multiple extensions",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"extensions": map[string]any{
					"health_check": map[string]any{},
					"pprof":        map[string]any{},
				},
				"service": map[string]any{
					"extensions": []string{"health_check", "pprof"},
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "pprof" extension: port conflict`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "exporter with failed to start pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"exporters": map[string]any{
					"otlp": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers": []string{"nop"},
							"exporters": []string{"otlp"},
						},
					},
				},
			},
			err:         errors.New(`failed to start "otlp" exporter: connection refused`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
		{
			name: "processor with for id pattern",
			config: map[string]any{
				"receivers": map[string]any{
					"nop": map[string]any{},
				},
				"processors": map[string]any{
					"batch": map[string]any{},
				},
				"exporters": map[string]any{
					"nop": map[string]any{},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"traces": map[string]any{
							"receivers":  []string{"nop"},
							"processors": []string{"batch"},
							"exporters":  []string{"nop"},
						},
					},
				},
			},
			err:         errors.New(`configuration error for id: "batch"`),
			expectError: false,
			validateResult: func(t *testing.T, cfg map[string]any, inputErr error, result *status.AggregateStatus) {
				require.NotNil(t, result)
				assert.Equal(t, componentstatus.StatusFatalError, result.Status())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := confmap.NewFromStringMap(tt.config)
			result, err := otelConfigToStatus(cfg, tt.err)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				if tt.validateResult != nil {
					tt.validateResult(t, tt.config, tt.err, result)
				}
			}
		})
	}
}

func TestRecordSpecificErr(t *testing.T) {
	tests := []struct {
		name           string
		componentID    string
		componentKind  component.Kind
		err            error
		extraMatchStrs []string
		expectMatch    bool
		isExtension    bool // extensions don't need pipeline IDs
	}{
		{
			name:          "match on 'for id:' pattern",
			componentID:   "otlp",
			componentKind: component.KindReceiver,
			err:           errors.New(`configuration error for id: "otlp"`),
			expectMatch:   true,
		},
		{
			name:          "match on 'failed to start' pattern for receiver",
			componentID:   "otlp",
			componentKind: component.KindReceiver,
			err:           errors.New(`failed to start "otlp" receiver: some error`),
			expectMatch:   true,
		},
		{
			name:          "match on 'failed to start' pattern for exporter",
			componentID:   "otlp",
			componentKind: component.KindExporter,
			err:           errors.New(`failed to start "otlp" exporter: some error`),
			expectMatch:   true,
		},
		{
			name:          "match on 'failed to start' pattern for processor",
			componentID:   "batch",
			componentKind: component.KindProcessor,
			err:           errors.New(`failed to start "batch" processor: invalid config`),
			expectMatch:   true,
		},
		{
			name:          "match on 'failed to start' pattern for extension",
			componentID:   "health_check",
			componentKind: component.KindExtension,
			err:           errors.New(`failed to start "health_check" extension: port in use`),
			expectMatch:   true,
			isExtension:   true,
		},
		{
			name:          "no match - different component id",
			componentID:   "otlp",
			componentKind: component.KindReceiver,
			err:           errors.New(`failed to start "nop" receiver: some error`),
			expectMatch:   false,
		},
		{
			name:          "no match - generic error",
			componentID:   "otlp",
			componentKind: component.KindReceiver,
			err:           errors.New("some generic error without component reference"),
			expectMatch:   false,
		},
		{
			name:           "match on extra match string",
			componentID:    "forward",
			componentKind:  component.KindConnector,
			err:            errors.New(`connector "forward" used as exporter failed`),
			extraMatchStrs: []string{`connector "forward" used as`},
			expectMatch:    true,
		},
		{
			name:           "no match on extra match string - different connector",
			componentID:    "forward",
			componentKind:  component.KindConnector,
			err:            errors.New(`connector "other" used as exporter failed`),
			extraMatchStrs: []string{`connector "forward" used as`},
			expectMatch:    false,
		},
		{
			name:           "match on second extra match string",
			componentID:    "forward",
			componentKind:  component.KindConnector,
			err:            errors.New(`second pattern match`),
			extraMatchStrs: []string{"first pattern", "second pattern"},
			expectMatch:    true,
		},
		{
			name:          "component id with slash - for id pattern",
			componentID:   "otlp/custom",
			componentKind: component.KindReceiver,
			err:           errors.New(`error for id: "otlp/custom"`),
			expectMatch:   true,
		},
		{
			name:          "component id with slash - failed to start pattern",
			componentID:   "otlp/custom",
			componentKind: component.KindReceiver,
			err:           errors.New(`failed to start "otlp/custom" receiver: error`),
			expectMatch:   true,
		},
		{
			name:          "extension with for id pattern",
			componentID:   "health_check",
			componentKind: component.KindExtension,
			err:           errors.New(`error for id: "health_check"`),
			expectMatch:   true,
			isExtension:   true,
		},
		{
			name:          "match on 'factory not available' pattern for receiver",
			componentID:   "invalid_receiver",
			componentKind: component.KindReceiver,
			err:           errors.New(`receiver factory not available for: "invalid_receiver"`),
			expectMatch:   true,
		},
		{
			name:          "match on 'factory not available' pattern for exporter",
			componentID:   "invalid_exporter",
			componentKind: component.KindExporter,
			err:           errors.New(`exporter factory not available for: "invalid_exporter"`),
			expectMatch:   true,
		},
		{
			name:          "match on 'factory not available' pattern for processor",
			componentID:   "invalid_processor",
			componentKind: component.KindProcessor,
			err:           errors.New(`processor factory not available for: "invalid_processor"`),
			expectMatch:   true,
		},
		{
			name:          "match on 'factory not available' pattern for extension",
			componentID:   "invalid_extension",
			componentKind: component.KindExtension,
			err:           errors.New(`extension factory not available for: "invalid_extension"`),
			expectMatch:   true,
			isExtension:   true,
		},
		{
			name:          "no match on 'factory not available' - different component",
			componentID:   "otlp",
			componentKind: component.KindReceiver,
			err:           errors.New(`receiver factory not available for: "invalid_receiver"`),
			expectMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := status.NewAggregator(status.PriorityPermanent)

			// Parse component ID (handle IDs with slashes like "otlp/custom")
			baseType := tt.componentID
			name := ""
			for i, c := range tt.componentID {
				if c == '/' {
					baseType = tt.componentID[:i]
					name = tt.componentID[i+1:]
					break
				}
			}

			componentType, err := component.NewType(baseType)
			require.NoError(t, err)

			var compID component.ID
			if name != "" {
				compID = component.NewIDWithName(componentType, name)
			} else {
				compID = component.NewID(componentType)
			}

			// Create instance ID - extensions don't need pipeline IDs, others do
			var instanceID *componentstatus.InstanceID
			if tt.isExtension {
				instanceID = componentstatus.NewInstanceID(compID, tt.componentKind)
			} else {
				// Use a dummy pipeline ID for non-extensions
				pipelineID := pipeline.NewID(pipeline.SignalTraces)
				instanceID = componentstatus.NewInstanceID(compID, tt.componentKind, pipelineID)
			}

			result := recordSpecificErr(agg, instanceID, tt.err, tt.extraMatchStrs...)

			assert.Equal(t, tt.expectMatch, result)

			// Verify the aggregator recorded the correct status
			aggStatus, _ := agg.AggregateStatus(status.ScopeAll, status.Verbose)
			require.NotNil(t, aggStatus)

			if tt.expectMatch {
				// Should have fatal error status
				assert.Equal(t, componentstatus.StatusFatalError, aggStatus.Status())
			} else {
				// Should have starting status (non-matched components get StatusStarting)
				assert.Equal(t, componentstatus.StatusStarting, aggStatus.Status())
			}
		})
	}
}
