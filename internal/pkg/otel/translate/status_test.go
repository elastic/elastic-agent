// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	serializablestatus "github.com/elastic/elastic-agent/internal/pkg/otel/status"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/version"
)

func TestGetAllComponentState(t *testing.T) {
	fileStreamOtelComponent := component.Component{
		ID:             "filestream-default",
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
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
			expectedErr: fmt.Errorf("couldn't parse otel status id: %s", fmt.Sprintf("logs/%sfilestream-default", OtelNamePrefix)),
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
						Message: "Healthy",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							runtime.ComponentUnitKey{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
								State:   client.UnitStateHealthy,
								Message: "Healthy",
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
								Message: "Healthy",
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
		{
			name:       "component state starting",
			components: []component.Component{fileStreamOtelComponent},
			otelStatus: &status.AggregateStatus{
				Event:              componentstatus.NewEvent(componentstatus.StatusStarting),
				ComponentStatusMap: map[string]*status.AggregateStatus{},
			},
			expected: []runtime.ComponentComponentState{
				{
					Component: fileStreamOtelComponent,
					State: runtime.ComponentState{
						State:   client.UnitStateStarting,
						Message: "STARTING",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							runtime.ComponentUnitKey{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
								State:   client.UnitStateStarting,
								Message: "Starting",
								Payload: map[string]any{
									"streams": map[string]map[string]string{
										"test-1": {
											"error":  "",
											"status": client.UnitStateStarting.String(),
										},
										"test-2": {
											"error":  "",
											"status": client.UnitStateStarting.String(),
										},
									},
								},
							},
							runtime.ComponentUnitKey{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
								State:   client.UnitStateStarting,
								Message: "Starting",
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
		s, err := DropComponentStateFromOtelStatus(nil)
		require.NoError(t, err)
		require.Nil(t, s)
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
		s, err := DropComponentStateFromOtelStatus(otelStatus)
		require.NoError(t, err)
		assert.Len(t, s.ComponentStatusMap, 1)
		assert.Contains(t, s.ComponentStatusMap, "pipeline:logs")
	})

	t.Run("invalid status", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			ComponentStatusMap: map[string]*status.AggregateStatus{
				"logs": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
			},
		}
		s, err := DropComponentStateFromOtelStatus(otelStatus)
		require.Error(t, err)
		require.Nil(t, s)
		assert.Equal(t, "couldn't parse otel status id: logs", err.Error())
	})

	t.Run("ignore extensions", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			ComponentStatusMap: map[string]*status.AggregateStatus{
				"extensions": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
				},
			},
		}
		s, err := DropComponentStateFromOtelStatus(otelStatus)
		require.NoError(t, err)
		assert.Equal(t, otelStatus, s)
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
			err:      "couldn't parse otel status id: invalid-format",
		},
		{
			name: "extensions are ignored",
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"extensions": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expected: map[string]*status.AggregateStatus{},
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
	comp := &component.Component{
		ID:             "test-component",
		RuntimeManager: component.OtelRuntimeManager,
		Units: []component.Unit{
			unit,
			{
				ID:   "output-1",
				Type: client.UnitTypeOutput,
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
				Message: "Healthy",
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
				Message: "Recoverable: recoverable error",
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "Recoverable: recoverable error",
							"status": client.UnitStateDegraded.String(),
						},
						"stream-2": {
							"error":  "Recoverable: recoverable error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getComponentUnitState(tt.status, unit, comp)
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
		expectedErr      error
	}{
		{"pipeline:logs", "pipeline", "logs", nil},
		{"pipeline:logs/filestream-monitoring", "pipeline", "logs/filestream-monitoring", nil},
		{"receiver:filebeat/filestream-monitoring", "receiver", "filebeat/filestream-monitoring", nil},
		{"exporter:elasticsearch/default", "exporter", "elasticsearch/default", nil},
		{"invalid", "", "", fmt.Errorf("couldn't parse otel status id: %s", "invalid")},
		{"", "", "", fmt.Errorf("couldn't parse otel status id: %s", "")},
		{"extensions", "extensions", "", nil},
	}

	for _, test := range tests {
		componentKind, pipelineId, err := ParseEntityStatusId(test.id)
		assert.Equal(t, test.expectedErr, err)
		assert.Equal(t, test.expectedKind, componentKind, "component kind")
		assert.Equal(t, test.expectedEntityID, pipelineId, "pipeline id")
	}
}

func TestHasStatus(t *testing.T) {
	scenarios := []struct {
		Name   string
		Result bool
		Has    componentstatus.Status
		Status *status.AggregateStatus
	}{
		{
			Name:   "empty",
			Result: false,
			Has:    componentstatus.StatusOK,
			Status: nil,
		},
		{
			Name:   "has status",
			Result: true,
			Has:    componentstatus.StatusOK,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
		},
		{
			Name:   "doesn't have status",
			Result: false,
			Has:    componentstatus.StatusRecoverableError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
		},
		{
			Name:   "sub-component has status",
			Result: true,
			Has:    componentstatus.StatusRecoverableError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"test-component": &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
					},
				},
			},
		},
		{
			Name:   "sub-component doesn't have status",
			Result: false,
			Has:    componentstatus.StatusPermanentError,
			Status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"test-component": &status.AggregateStatus{
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
					},
				},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			observed := HasStatus(scenario.Status, scenario.Has)
			assert.Equal(t, scenario.Result, observed)
		})
	}
}

func TestStateWithMessage(t *testing.T) {
	tests := []struct {
		name          string
		otelStatus    *status.AggregateStatus
		expectedState client.UnitState
		expectedMsg   string
	}{
		{
			name: "StatusNone",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusNone),
			},
			expectedState: client.UnitStateHealthy,
			expectedMsg:   "Healthy",
		},
		{
			name: "StatusStarting",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusStarting),
			},
			expectedState: client.UnitStateStarting,
			expectedMsg:   "Starting",
		},
		{
			name: "StatusOK",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expectedState: client.UnitStateHealthy,
			expectedMsg:   "Healthy",
		},
		{
			name: "StatusRecoverableError",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewRecoverableErrorEvent(errors.New("test recoverable error")),
			},
			expectedState: client.UnitStateDegraded,
			expectedMsg:   "Recoverable: test recoverable error",
		},
		{
			name: "StatusRecoverableError without error",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
			},
			expectedState: client.UnitStateDegraded,
			expectedMsg:   "Unknown recoverable error",
		},
		{
			name: "StatusPermanentError",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewPermanentErrorEvent(errors.New("test permanent error")),
			},
			expectedState: client.UnitStateFailed,
			expectedMsg:   "Permanent: test permanent error",
		},
		{
			name: "StatusPermanentError without error",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusPermanentError),
			},
			expectedState: client.UnitStateFailed,
			expectedMsg:   "Unknown permanent error",
		},
		{
			name: "StatusFatalError",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewFatalErrorEvent(errors.New("test fatal error")),
			},
			expectedState: client.UnitStateFailed,
			expectedMsg:   "Fatal: test fatal error",
		},
		{
			name: "StatusFatalError without error",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusFatalError),
			},
			expectedState: client.UnitStateFailed,
			expectedMsg:   "Unknown fatal error",
		},
		{
			name: "StatusStopping",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusStopping),
			},
			expectedState: client.UnitStateStopping,
			expectedMsg:   "Stopping",
		},
		{
			name: "StatusStopped",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusStopped),
			},
			expectedState: client.UnitStateStopped,
			expectedMsg:   "Stopped",
		},
		{
			name: "Unknown status",
			otelStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.Status(999)), // Simulate an unknown status
			},
			expectedState: client.UnitStateFailed,
			expectedMsg:   "Unknown component status: StatusNone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, msg := StateWithMessage(tt.otelStatus)
			assert.Equal(t, tt.expectedState, state)
			assert.Equal(t, tt.expectedMsg, msg)
		})
	}
}

func TestGetComponentUnitStateWithStreamAttributes(t *testing.T) {
	unit := component.Unit{
		ID:   "filestream-unit",
		Type: client.UnitTypeInput,
		Config: &proto.UnitExpectedConfig{
			Streams: []*proto.Stream{
				{Id: "stream-1"},
				{Id: "stream-2"},
			},
		},
	}
	comp := &component.Component{
		ID:             "test-component",
		RuntimeManager: component.OtelRuntimeManager,
		Units: []component.Unit{
			unit,
			{
				ID:   "output-1",
				Type: client.UnitTypeOutput,
			},
		},
	}

	tests := []struct {
		name     string
		status   *status.AggregateStatus
		expected runtime.ComponentUnitState
	}{
		{
			name: "stream statuses from attributes - all healthy",
			status: aggregateStatusWithAttributes(
				componentstatus.StatusOK,
				nil,
				map[string]any{
					"inputs": map[string]any{
						"stream-1": map[string]any{
							"status": "StatusOK",
							"error":  "",
						},
						"stream-2": map[string]any{
							"status": "StatusOK",
							"error":  "",
						},
					},
				},
			),
			// When all streams are healthy, unitStateFromStreamStatuses returns (Healthy, "")
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateHealthy,
				Message: "",
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
			name: "stream statuses from attributes - one degraded",
			status: aggregateStatusWithAttributes(
				componentstatus.StatusOK,
				nil,
				map[string]any{
					"inputs": map[string]any{
						"stream-1": map[string]any{
							"status": "StatusOK",
							"error":  "",
						},
						"stream-2": map[string]any{
							"status": "StatusRecoverableError",
							"error":  "stream error",
						},
					},
				},
			),
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateDegraded,
				Message: "Recoverable: stream error",
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "",
							"status": client.UnitStateHealthy.String(),
						},
						"stream-2": {
							"error":  "Recoverable: stream error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
		{
			name: "stream statuses from attributes - one failed",
			status: aggregateStatusWithAttributes(
				componentstatus.StatusOK,
				nil,
				map[string]any{
					"inputs": map[string]any{
						"stream-1": map[string]any{
							"status": "StatusPermanentError",
							"error":  "permanent error",
						},
						"stream-2": map[string]any{
							"status": "StatusRecoverableError",
							"error":  "recoverable error",
						},
					},
				},
			),
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateFailed,
				Message: "Permanent: permanent error",
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "Permanent: permanent error",
							"status": client.UnitStateFailed.String(),
						},
						"stream-2": {
							"error":  "Recoverable: recoverable error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
		{
			name: "partial stream statuses from attributes - missing stream uses top level for payload",
			status: aggregateStatusWithAttributes(
				componentstatus.StatusRecoverableError,
				errors.New("top level error"),
				map[string]any{
					"inputs": map[string]any{
						"stream-1": map[string]any{
							"status": "StatusOK",
							"error":  "",
						},
						// stream-2 is missing, uses top level status for payload
					},
				},
			),
			// Unit state is computed only from reported stream statuses (stream-1 = healthy)
			// so unit state is Healthy. Payload includes stream-2 with top level status.
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateHealthy,
				Message: "",
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "",
							"status": client.UnitStateHealthy.String(),
						},
						"stream-2": {
							"error":  "Recoverable: top level error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
		{
			name: "no stream statuses in attributes - uses top level state",
			status: aggregateStatusWithAttributes(
				componentstatus.StatusRecoverableError,
				errors.New("top level error"),
				map[string]any{
					"inputs": map[string]any{
						// No stream statuses provided
					},
				},
			),
			// When no stream statuses are reported, unit state is computed from top level
			expected: runtime.ComponentUnitState{
				State:   client.UnitStateDegraded,
				Message: "Recoverable: top level error",
				Payload: map[string]any{
					"streams": map[string]map[string]string{
						"stream-1": {
							"error":  "Recoverable: top level error",
							"status": client.UnitStateDegraded.String(),
						},
						"stream-2": {
							"error":  "Recoverable: top level error",
							"status": client.UnitStateDegraded.String(),
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getComponentUnitState(tt.status, unit, comp)
			assert.Equal(t, tt.expected.State, result.State)
			assert.Equal(t, tt.expected.Message, result.Message)
			assert.Equal(t, tt.expected.Payload, result.Payload)
		})
	}
}

func TestGetComponentUnitStateWithUnitInputStatus(t *testing.T) {
	// Test the unit aggStatus from input attributes path
	// This can only happen for filestream, which is allowed to not have streams defined
	unit := component.Unit{
		ID:   "filestream-default-filestream-1", // This is what the component package sets as the unit id if there's no stream defined
		Type: client.UnitTypeInput,
		Config: &proto.UnitExpectedConfig{
			Streams: []*proto.Stream{},
		},
	}
	comp := &component.Component{
		ID:             "filestream-default",
		RuntimeManager: component.OtelRuntimeManager,
		Units: []component.Unit{
			unit,
			{
				ID:   "output-1",
				Type: client.UnitTypeOutput,
			},
		},
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Command: &component.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
	}

	aggStatus := aggregateStatusWithAttributes(
		componentstatus.StatusOK,
		nil,
		map[string]any{
			"inputs": map[string]any{
				"filestream-1": map[string]any{
					"status": "StatusRecoverableError",
					"error":  "unit level error",
				},
			},
		},
	)

	expectedState := runtime.ComponentUnitState{
		State:   client.UnitStateDegraded,
		Message: "Recoverable: unit level error",
		Payload: nil,
	}

	result := getComponentUnitState(aggStatus, unit, comp)
	assert.Equal(t, expectedState.State, result.State)
	assert.Equal(t, expectedState.Message, result.Message)
	assert.Equal(t, expectedState.Payload, result.Payload)
}

func TestUnitStateFromStreamStatuses(t *testing.T) {
	tests := []struct {
		name            string
		streamStatuses  map[string]*serializablestatus.SerializableEvent
		expectedState   client.UnitState
		expectedMessage string
	}{
		{
			name: "all healthy",
			streamStatuses: map[string]*serializablestatus.SerializableEvent{
				"stream-1": {StatusString: "StatusOK"},
				"stream-2": {StatusString: "StatusOK"},
			},
			expectedState:   client.UnitStateHealthy,
			expectedMessage: "",
		},
		{
			name: "one degraded",
			streamStatuses: map[string]*serializablestatus.SerializableEvent{
				"stream-1": {StatusString: "StatusOK"},
				"stream-2": {StatusString: "StatusRecoverableError", Error: "degraded error"},
			},
			expectedState:   client.UnitStateDegraded,
			expectedMessage: "Recoverable: degraded error",
		},
		{
			name: "one failed - takes precedence",
			streamStatuses: map[string]*serializablestatus.SerializableEvent{
				"stream-1": {StatusString: "StatusPermanentError", Error: "failed error"},
				"stream-2": {StatusString: "StatusRecoverableError", Error: "degraded error"},
			},
			expectedState:   client.UnitStateFailed,
			expectedMessage: "Permanent: failed error",
		},
		{
			name:            "empty stream statuses",
			streamStatuses:  map[string]*serializablestatus.SerializableEvent{},
			expectedState:   client.UnitStateHealthy,
			expectedMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, message := unitStateFromStreamStatuses(tt.streamStatuses)
			assert.Equal(t, tt.expectedState, state)
			assert.Equal(t, tt.expectedMessage, message)
		})
	}
}

// aggregateStatusWithAttributes creates an AggregateStatus with attributes for testing.
func aggregateStatusWithAttributes(s componentstatus.Status, err error, attributes map[string]any) *status.AggregateStatus {
	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	event, _ := serializablestatus.FromSerializableEvent(&serializablestatus.SerializableEvent{
		StatusString: s.String(), // Status.String() returns "StatusOK", "StatusRecoverableError", etc.
		Error:        errStr,
		Attributes:   attributes,
	})
	return &status.AggregateStatus{
		Event:              event,
		ComponentStatusMap: make(map[string]*status.AggregateStatus),
	}
}

func TestOutputStatus(t *testing.T) {
	baseComp := component.Component{
		ID:             "filestream-default",
		InputType:      "filestream",
		OutputType:     "elasticsearch",
		RuntimeManager: component.OtelRuntimeManager,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
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

	tests := []struct {
		name                  string
		status                *status.AggregateStatus
		outputStatusReporting bool
		expected              runtime.ComponentComponentState
	}{
		{
			name:                  "output status reporting enabled - healthy exporter",
			outputStatusReporting: true,
			status: &status.AggregateStatus{
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
			expected: runtime.ComponentComponentState{
				Component: baseComp,
				State: runtime.ComponentState{
					State:   client.UnitStateHealthy, // recoverable error
					Message: "",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      OtelComponentName,
						BuildHash: version.Commit(),
						Meta: map[string]string{
							"build_time": version.BuildTime().String(),
							"commit":     version.Commit(),
						},
					},
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
							Payload: map[string]any{
								"streams": map[string]map[string]string{
									"test-1": {
										"error":  "",
										"status": "HEALTHY",
									},
									"test-2": {
										"error":  "",
										"status": "HEALTHY",
									},
								},
							},
						},
						{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
						},
					},
				},
			},
		},
		{
			name:                  "output status reporting enabled - degraded exporter",
			outputStatusReporting: true,
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("pipeline:logs/%sfilestream-default", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							fmt.Sprintf("receiver:filebeat/%sfilestream-unit", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							fmt.Sprintf("exporter:elasticsearch/%sfilestream-default", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
							},
						},
					},
				},
			},
			expected: runtime.ComponentComponentState{
				Component: baseComp,
				State: runtime.ComponentState{
					State:   client.UnitStateDegraded, // recoverable error
					Message: "",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      OtelComponentName,
						BuildHash: version.Commit(),
						Meta: map[string]string{
							"build_time": version.BuildTime().String(),
							"commit":     version.Commit(),
						},
					},
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
							Payload: map[string]any{
								"streams": map[string]map[string]string{
									"test-1": {
										"error":  "",
										"status": "HEALTHY",
									},
									"test-2": {
										"error":  "",
										"status": "HEALTHY",
									},
								},
							},
						},
						{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
							State:   client.UnitStateDegraded,
							Message: "Unknown recoverable error",
						},
					},
				},
			},
		},
		{
			name:                  "output status reporting disabled - healthy exporter",
			outputStatusReporting: false,
			status: &status.AggregateStatus{
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
			expected: runtime.ComponentComponentState{
				Component: baseComp,
				State: runtime.ComponentState{
					State:   client.UnitStateHealthy, // recoverable error
					Message: "",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      OtelComponentName,
						BuildHash: version.Commit(),
						Meta: map[string]string{
							"build_time": version.BuildTime().String(),
							"commit":     version.Commit(),
						},
					},
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
							Payload: map[string]any{
								"streams": map[string]map[string]string{
									"test-1": {
										"error":  "",
										"status": "HEALTHY",
									},
									"test-2": {
										"error":  "",
										"status": "HEALTHY",
									},
								},
							},
						},
						{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
						},
					},
				},
			},
		},
		{
			name:                  "output status reporting disabled - degraded exporter",
			outputStatusReporting: false,
			status: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					fmt.Sprintf("pipeline:logs/%sfilestream-default", OtelNamePrefix): {
						Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							fmt.Sprintf("receiver:filebeat/%sfilestream-unit", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							fmt.Sprintf("exporter:elasticsearch/%sfilestream-default", OtelNamePrefix): {
								Event: componentstatus.NewEvent(componentstatus.StatusRecoverableError),
							},
						},
					},
				},
			},
			expected: runtime.ComponentComponentState{
				Component: baseComp,
				State: runtime.ComponentState{
					State:   client.UnitStateHealthy, // recoverable error
					Message: "",
					VersionInfo: runtime.ComponentVersionInfo{
						Name:      OtelComponentName,
						BuildHash: version.Commit(),
						Meta: map[string]string{
							"build_time": version.BuildTime().String(),
							"commit":     version.Commit(),
						},
					},
					Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
						{UnitID: "filestream-unit", UnitType: client.UnitTypeInput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
							Payload: map[string]any{
								"streams": map[string]map[string]string{
									"test-1": {
										"error":  "",
										"status": "HEALTHY",
									},
									"test-2": {
										"error":  "",
										"status": "HEALTHY",
									},
								},
							},
						},
						{UnitID: "filestream-default", UnitType: client.UnitTypeOutput}: {
							State:   client.UnitStateHealthy,
							Message: "Healthy",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy of the base component and apply test-specific config
			comp := baseComp
			comp.OutputStatusReporting = &component.StatusReporting{
				Enabled: tt.outputStatusReporting,
			}

			status, err := MaybeMuteExporterStatus(tt.status, []component.Component{comp})
			require.NoError(t, err)
			result, err := getComponentState(status.ComponentStatusMap["pipeline:logs/_agent-component/filestream-default"], comp)
			require.NoError(t, err)
			assert.Equal(t, tt.expected.Component.ID, result.Component.ID)
			assert.Equal(t, tt.expected.State.State, result.State.State)
			assert.Equal(t, len(tt.expected.State.Units), len(result.State.Units))
			assert.Equal(t, tt.expected.State.Units, result.State.Units)
		})
	}
}
