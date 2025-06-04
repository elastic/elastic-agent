// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/version"

	"github.com/stretchr/testify/assert"
)

func TestGetAllComponentState(t *testing.T) {
	fileStreamOtelComponent := component.Component{
		ID:             "filestream-default",
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "agentbeat",
			Spec: component.InputSpec{
				Command: &component.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "filestream-unit",
				Type: client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{
					Streams: []*proto.Stream{
						{Id: "test-1"},
						{Id: "test-2"},
					},
				},
			},
			{
				ID:   "filestream-default",
				Type: client.UnitTypeOutput,
			},
		},
	}
	fileStreamProcessComponent := fileStreamOtelComponent
	fileStreamProcessComponent.RuntimeManager = component.ProcessRuntimeManager
	tests := []struct {
		name        string
		components  []component.Component
		otelStatus  *status.AggregateStatus
		expected    []runtime.ComponentComponentState
		expectedErr error
	}{
		{
			name:       "empty",
			components: []component.Component{},
			otelStatus: nil,
		},
		{
			name: "invalid status",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("logs/%sfilestream-default", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expectedErr: fmt.Errorf("pipeline status id %s is not a pipeline", fmt.Sprintf("logs/%sfilestream-default", OtelNamePrefix)),
		},
		{
			name:       "one otel component, one process component",
			components: []component.Component{fileStreamOtelComponent, fileStreamProcessComponent},
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("pipeline:logs/%sfilestream-default", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							fmt.Sprintf("receiver:filebeat/%sfilestream-unit", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							fmt.Sprintf("exporter:elasticsearch/%sfilestream-default", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
				},
			},
			expected: []runtime.ComponentComponentState{
				{
					Component: fileStreamOtelComponent,
					State: runtime.ComponentState{
						State:   client.UnitStateHealthy,
						Message: "StatusOK",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							runtime.ComponentUnitKey{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
								State:   client.UnitStateHealthy,
								Message: client.UnitStateHealthy.String(),
								Payload: map[string]any{
									"streams": map[string]map[string]string{
										"test-1": {
											"error":  "",
											"status": client.UnitStateHealthy.String(),
										},
										"test-2": {
											"error":  "",
											"status": client.UnitStateHealthy.String(),
										},
									},
								},
							},
							runtime.ComponentUnitKey{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
								State:   client.UnitStateHealthy,
								Message: client.UnitStateHealthy.String(),
							},
						},
						VersionInfo: runtime.ComponentVersionInfo{
							Name:      OtelComponentName,
							BuildHash: version.Commit(),
							Meta: map[string]string{
								"build_time": version.BuildTime().String(),
								"commit":     version.Commit(),
							},
						},
					},
				},
			},
		},
		{
			name:       "component missing from otel status",
			components: []component.Component{fileStreamOtelComponent, fileStreamProcessComponent},
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"receiver:filelog": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"exporter:elasticsearch": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
				},
			},
			expected: []runtime.ComponentComponentState{
				{
					Component: fileStreamOtelComponent,
					State: runtime.ComponentState{
						State: client.UnitStateStopped,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			componentStates, err := GetAllComponentStates(test.otelStatus, test.components)
			assert.Equal(t, test.expected, componentStates)
			assert.Equal(t, test.expectedErr, err)
		})
	}
}

func TestDropComponentStateFromOtelStatus(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		err := DropComponentStateFromOtelStatus(nil)
		require.NoError(t, err)
	})

	t.Run("drop non otel", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			ComponentStatusMap: map[string]*status.AggregateStatus{
				"pipeline:logs": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
				fmt.Sprintf("pipeline:logs/%sfilestream-default", OtelNamePrefix): {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
			},
		}
		err := DropComponentStateFromOtelStatus(otelStatus)
		require.NoError(t, err)
		assert.Len(t, otelStatus.ComponentStatusMap, 1)
		assert.Contains(t, otelStatus.ComponentStatusMap, "pipeline:logs")
	})

	t.Run("invalid status", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			ComponentStatusMap: map[string]*status.AggregateStatus{
				"logs": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
			},
		}
		err := DropComponentStateFromOtelStatus(otelStatus)
		require.Error(t, err)
		assert.Equal(t, "pipeline status id logs is not a pipeline", err.Error())
	})
}

func TestGetOtelRuntimePipelineStatuses(t *testing.T) {
	tests := []struct {
		name     string
		status   *status.AggregateStatus
		expected map[string]*status.AggregateStatus
		err      string
	}{
		{
			name:   "nil status",
			status: nil,
			// Should return empty map, no error
			expected: map[string]*status.AggregateStatus{},
			err:      "",
		},
		{
			name: "valid otel pipeline status",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					fmt.Sprintf("pipeline:logs/%sfilestream-default", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expected: map[string]*status.AggregateStatus{
				"filestream-default": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
			},
			err: "",
		},
		{
			name: "invalid pipeline status format",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"invalid-format": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expected: nil,
			err:      "pipeline status id invalid-format is not a pipeline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getOtelRuntimePipelineStatuses(tt.status)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
			} else {
				require.NoError(t, err)
				if tt.expected == nil {
					assert.Nil(t, result)
				} else {
					assert.Equal(t, len(tt.expected), len(result))
					for k, v := range tt.expected {
						assert.Contains(t, result, k)
						assert.Equal(t, v.Status(), result[k].Status())
					}
				}
			}
		})
	}
}

func TestGetComponentStatus(t *testing.T) {
	comp := component.Component{
		ID:             "test-component",
		RuntimeManager: component.OtelRuntimeManager,
		Units: []component.Unit{
			{
				ID:   "input-1",
				Type: client.UnitTypeInput,
				Config: &proto.UnitExpectedConfig{
					Streams: []*proto.Stream{{Id: "stream-1"}},
				},
			},
			{
				ID:   "output-1",
				Type: client.UnitTypeOutput,
			},
		},
	}

	tests := []struct {
		name     string
		status   *status.AggregateStatus
		expected runtime.ComponentComponentState
		err      string
	}{
		{
			name: "valid component status",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("receiver:filebeat/%sinput-1", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					fmt.Sprintf("exporter:elasticsearch/%soutput-1", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
					},
				},
			},
			expected: runtime.ComponentComponentState{
				Component: comp,
				State: runtime.ComponentState{
					State:   client.UnitStateDegraded, // Because of the recoverable error
					Message: "StatusRecoverableError",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      OtelComponentName,
						BuildHash: version.Commit(),
						Meta: map[string]string{
							"build_time": version.BuildTime().String(),
							"commit":     version.Commit(),
						},
					},
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{UnitID: "input-1", UnitType: client.UnitTypeInput}: {
							State:   client.UnitStateHealthy,
							Message: client.UnitStateHealthy.String(),
							Payload: map[string]any{
								"streams": map[string]map[string]string{
									"stream-1": {
										"error":  "",
										"status": client.UnitStateHealthy.String(),
									},
								},
							},
						},
						{UnitID: "output-1", UnitType: client.UnitTypeOutput}: {
							State:   client.UnitStateDegraded,
							Message: client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
		{
			name: "multiple receivers should error",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("receiver:filebeat/%sotel-input-1", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					fmt.Sprintf("receiver:filebeat/%sotel-input-2", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			err: "expected at most one receiver",
		},
		{
			name: "multiple exporters should error",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("receiver:filebeat/%sotel-input-1", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					fmt.Sprintf("receiver:filebeat/%sotel-input-2", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			err: "expected at most one receiver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getComponentState(tt.status, comp)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
			} else {
				require.NoError(t, err)
				// Can't compare the entire struct directly because of unexported fields
				assert.Equal(t, tt.expected.Component.ID, result.Component.ID)
				assert.Equal(t, tt.expected.State.State, result.State.State)
				assert.Equal(t, len(tt.expected.State.Units), len(result.State.Units))
			}
		})
	}
}

func TestGetComponentUnitState(t *testing.T) {
	unit := component.Unit{
		ID:   "test-unit",
		Type: client.UnitTypeInput,
		Config: &proto.UnitExpectedConfig{
			Streams: []*proto.Stream{
				{Id: "stream-1"},
				{Id: "stream-2"},
			},
		},
	}

	tests := []struct {
		name     string
		status   *status.AggregateStatus
		expected runtime.ComponentUnitState
	}{
		{
			name: "healthy status",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateHealthy,
				Message: client.UnitStateHealthy.String(),
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "",
							"status": client.UnitStateHealthy.String(),
						},
						"stream-2": {
							"error":  "",
							"status": client.UnitStateHealthy.String(),
						},
					},
				},
			},
		},
		{
			name: "error status",
			status: &status.AggregateStatus{
				Event: componentstatus.NewRecoverableErrorEvent(errors.New("recoverable error")),
			},
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateDegraded,
				Message: client.UnitStateDegraded.String(),
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "recoverable error",
							"status": client.UnitStateDegraded.String(),
						},
						"stream-2": {
							"error":  "recoverable error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getComponentUnitState(tt.status, unit)
			assert.Equal(t, tt.expected.State, result.State)
			assert.Equal(t, tt.expected.Message, result.Message)
			assert.Equal(t, tt.expected.Payload, result.Payload)
		})
	}
}

func TestParseEntityStatusId(t *testing.T) {
	tests := []struct {
		id               string
		expectedKind     string
		expectedEntityID string
	}{
		{"pipeline:logs", "pipeline", "logs"},
		{"pipeline:logs/filestream-monitoring", "pipeline", "logs/filestream-monitoring"},
		{"receiver:filebeat/filestream-monitoring", "receiver", "filebeat/filestream-monitoring"},
		{"exporter:elasticsearch/default", "exporter", "elasticsearch/default"},
		{"invalid", "", ""},
	}

	for _, test := range tests {
		componentKind, pipelineId := parseEntityStatusId(test.id)
		assert.Equal(t, test.expectedKind, componentKind, "component kind")
		assert.Equal(t, test.expectedEntityID, pipelineId, "pipeline id")
	}
}

func TestOtelStatusToUnitState(t *testing.T) {
	tests := []struct {
		name     string
		status   componentstatus.Status
		expected client.UnitState
	}{
		{
			name:     "StatusNone",
			status:   componentstatus.StatusNone,
			expected: client.UnitStateDegraded,
		},
		{
			name:     "StatusStarting",
			status:   componentstatus.StatusStarting,
			expected: client.UnitStateStarting,
		},
		{
			name:     "StatusOK",
			status:   componentstatus.StatusOK,
			expected: client.UnitStateHealthy,
		},
		{
			name:     "StatusRecoverableError",
			status:   componentstatus.StatusRecoverableError,
			expected: client.UnitStateDegraded,
		},
		{
			name:     "StatusPermanentError",
			status:   componentstatus.StatusPermanentError,
			expected: client.UnitStateFailed,
		},
		{
			name:     "StatusFatalError",
			status:   componentstatus.StatusFatalError,
			expected: client.UnitStateFailed,
		},
		{
			name:     "StatusStopping",
			status:   componentstatus.StatusStopping,
			expected: client.UnitStateStopping,
		},
		{
			name:     "StatusStopped",
			status:   componentstatus.StatusStopped,
			expected: client.UnitStateStopped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := otelStatusToUnitState(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}
