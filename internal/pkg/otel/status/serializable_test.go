// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package status

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func TestCompareAggregateStatuses(t *testing.T) {
	timestamp := time.Now()
	attributes := pcommon.NewMap()
	attributes.PutStr("key", "value")

	for _, tc := range []struct {
		name     string
		s1, s2   *status.AggregateStatus
		expected bool
	}{
		{
			name: "equal statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			expected: true,
		},
		{
			name: "unequal statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusPermanentError,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			expected: false,
		},
		{
			name: "unequal errors",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        errors.New("error"),
				},
			},
			expected: false,
		},
		{
			name: "unequal attributes",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: attributes,
					err:        errors.New("error"),
				},
			},
			expected: false,
		},
		{
			name: "unequal component statuses",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusStopped,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "more components",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
					"component2": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "completely different components",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component3": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        nil,
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "unequal component errors",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        errors.New("error1"),
						},
					},
				},
			},
			s2: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
				ComponentStatusMap: map[string]*status.AggregateStatus{
					"component1": {
						Event: &healthCheckEvent{
							status:     componentstatus.StatusOK,
							timestamp:  timestamp,
							attributes: pcommon.NewMap(),
							err:        errors.New("error2"),
						},
					},
				},
			},
			expected: false,
		},
		{
			name:     "both nil",
			s1:       nil,
			s2:       nil,
			expected: true,
		},
		{
			name: "one nil",
			s1: &status.AggregateStatus{
				Event: &healthCheckEvent{
					status:     componentstatus.StatusOK,
					timestamp:  timestamp,
					attributes: pcommon.NewMap(),
					err:        nil,
				},
			},
			s2:       nil,
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual := CompareStatuses(tc.s1, tc.s2)
			assert.Equal(t, tc.expected, actual, "expected %v, got %v", tc.expected, actual)
		})
	}
}

func TestSerializableStatusJSONDeserialization(t *testing.T) {
	tests := []struct {
		name           string
		jsonInput      string
		expectedStatus componentstatus.Status
		expectedErr    string
		expectedComps  []string
		checkFn        func(t *testing.T, ss *SerializableStatus)
	}{
		{
			name: "simple healthy status",
			jsonInput: `{
				"healthy": true,
				"status": "StatusOK",
				"status_time": "2025-12-16T13:41:57.130417387+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusOK,
			expectedErr:    "",
			expectedComps:  nil,
		},
		{
			name: "status with start_time",
			jsonInput: `{
				"start_time": "2025-12-16T13:41:57.130417387+01:00",
				"healthy": true,
				"status": "StatusOK",
				"status_time": "2025-12-16T13:42:10.572796195+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusOK,
			checkFn: func(t *testing.T, ss *SerializableStatus) {
				require.NotNil(t, ss.StartTimestamp)
				assert.Equal(t, 2025, ss.StartTimestamp.Year())
			},
		},
		{
			name: "recoverable error status",
			jsonInput: `{
				"healthy": true,
				"status": "StatusRecoverableError",
				"error": "connection refused",
				"status_time": "2025-12-16T13:42:10.572796195+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusRecoverableError,
			expectedErr:    "connection refused",
		},
		{
			name: "permanent error status",
			jsonInput: `{
				"healthy": false,
				"status": "StatusPermanentError",
				"error": "fatal configuration error",
				"status_time": "2025-12-16T13:42:10.572796195+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusPermanentError,
			expectedErr:    "fatal configuration error",
		},
		{
			name: "status with nested components",
			jsonInput: `{
				"healthy": true,
				"status": "StatusOK",
				"status_time": "2025-12-16T13:41:57.130417387+01:00",
				"attributes": {},
				"components": {
					"extensions": {
						"healthy": true,
						"status": "StatusOK",
						"status_time": "2025-12-16T13:41:57.132361782+01:00",
						"attributes": {},
						"components": {
							"extension:healthcheckv2": {
								"healthy": true,
								"status": "StatusOK",
								"status_time": "2025-12-16T13:41:57.132201863+01:00",
								"attributes": {}
							}
						}
					},
					"pipeline:logs/test": {
						"healthy": true,
						"status": "StatusOK",
						"status_time": "2025-12-16T13:41:57.130417387+01:00",
						"attributes": {}
					}
				}
			}`,
			expectedStatus: componentstatus.StatusOK,
			expectedComps:  []string{"extensions", "pipeline:logs/test"},
			checkFn: func(t *testing.T, ss *SerializableStatus) {
				require.NotNil(t, ss.ComponentStatuses["extensions"])
				extStatus := ss.ComponentStatuses["extensions"]
				require.NotNil(t, extStatus.ComponentStatuses["extension:healthcheckv2"])
			},
		},
		{
			name: "status with attributes containing inputs",
			jsonInput: `{
				"healthy": true,
				"status": "StatusRecoverableError",
				"error": "some streams have errors",
				"status_time": "2025-12-16T13:45:03.605380788+01:00",
				"attributes": {
					"inputs": {
						"stream-1": {
							"error": "",
							"status": "StatusOK"
						},
						"stream-2": {
							"error": "stream error",
							"status": "StatusRecoverableError"
						}
					}
				}
			}`,
			expectedStatus: componentstatus.StatusRecoverableError,
			expectedErr:    "some streams have errors",
			checkFn: func(t *testing.T, ss *SerializableStatus) {
				require.NotNil(t, ss.Attributes)
				inputs, ok := ss.Attributes["inputs"]
				require.True(t, ok, "attributes should contain 'inputs'")
				inputsMap, ok := inputs.(map[string]any)
				require.True(t, ok, "inputs should be a map")
				assert.Len(t, inputsMap, 2)

				stream1, ok := inputsMap["stream-1"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "StatusOK", stream1["status"])
				assert.Equal(t, "", stream1["error"])

				stream2, ok := inputsMap["stream-2"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "StatusRecoverableError", stream2["status"])
				assert.Equal(t, "stream error", stream2["error"])
			},
		},
		{
			name: "all status types",
			jsonInput: `{
				"healthy": true,
				"status": "StatusStarting",
				"status_time": "2025-12-16T13:41:57.130417387+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusStarting,
		},
		{
			name: "unknown status defaults to StatusNone",
			jsonInput: `{
				"healthy": true,
				"status": "UnknownStatus",
				"status_time": "2025-12-16T13:41:57.130417387+01:00",
				"attributes": {}
			}`,
			expectedStatus: componentstatus.StatusNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ss SerializableStatus
			err := json.Unmarshal([]byte(tt.jsonInput), &ss)
			require.NoError(t, err, "JSON unmarshaling should not fail")

			// Check status
			aggStatus, err := FromSerializableStatus(&ss)
			require.NoError(t, err, "FromSerializableStatus should not fail")
			assert.Equal(t, tt.expectedStatus, aggStatus.Status())

			// Check error
			if tt.expectedErr != "" {
				require.NotNil(t, aggStatus.Err())
				assert.Equal(t, tt.expectedErr, aggStatus.Err().Error())
			} else {
				assert.Nil(t, aggStatus.Err())
			}

			// Check components
			if tt.expectedComps != nil {
				assert.Len(t, aggStatus.ComponentStatusMap, len(tt.expectedComps))
				for _, comp := range tt.expectedComps {
					assert.Contains(t, aggStatus.ComponentStatusMap, comp)
				}
			}

			// Run custom check function
			if tt.checkFn != nil {
				tt.checkFn(t, &ss)
			}
		})
	}
}

func TestSerializableStatusJSONDeserializationHealthcheckv2Format(t *testing.T) {
	// This test uses a real-world healthcheckv2 JSON output format
	jsonInput := `{
		"start_time": "2025-12-16T13:41:57.130417387+01:00",
		"healthy": true,
		"status": "StatusRecoverableError",
		"error": "Elasticsearch request failed: dial tcp 127.0.0.1:9200: connect: connection refused",
		"status_time": "2025-12-16T13:42:10.572796195+01:00",
		"attributes": {},
		"components": {
			"extensions": {
				"healthy": true,
				"status": "StatusOK",
				"status_time": "2025-12-16T13:41:57.132361782+01:00",
				"attributes": {},
				"components": {
					"extension:beatsauth/_agent-component/default": {
						"healthy": true,
						"status": "StatusOK",
						"status_time": "2025-12-16T13:41:57.131889585+01:00",
						"attributes": {}
					},
					"extension:healthcheckv2/test-id": {
						"healthy": true,
						"status": "StatusOK",
						"status_time": "2025-12-16T13:41:57.132201863+01:00",
						"attributes": {}
					}
				}
			},
			"pipeline:logs/_agent-component/system/metrics-default": {
				"healthy": true,
				"status": "StatusRecoverableError",
				"error": "Elasticsearch request failed: dial tcp 127.0.0.1:9200: connect: connection refused",
				"status_time": "2025-12-16T13:42:10.572796195+01:00",
				"attributes": {},
				"components": {
					"exporter:elasticsearch/_agent-component/default": {
						"healthy": true,
						"status": "StatusRecoverableError",
						"error": "Elasticsearch request failed: dial tcp 127.0.0.1:9200: connect: connection refused",
						"status_time": "2025-12-16T13:42:10.572796195+01:00",
						"attributes": {}
					},
					"receiver:metricbeatreceiver/_agent-component/system/metrics-default": {
						"healthy": true,
						"status": "StatusRecoverableError",
						"error": "Error fetching data for metricset system.process",
						"status_time": "2025-12-16T13:45:03.605380788+01:00",
						"attributes": {
							"inputs": {
								"unique-system-metrics-input-cpu": {
									"error": "",
									"status": "StatusOK"
								},
								"unique-system-metrics-input-process": {
									"error": "permission denied",
									"status": "StatusRecoverableError"
								}
							}
						}
					}
				}
			}
		}
	}`

	var ss SerializableStatus
	err := json.Unmarshal([]byte(jsonInput), &ss)
	require.NoError(t, err, "JSON unmarshaling should not fail")

	// Verify top-level status
	aggStatus, err := FromSerializableStatus(&ss)
	require.NoError(t, err, "FromSerializableStatus should not fail")
	assert.Equal(t, componentstatus.StatusRecoverableError, aggStatus.Status())
	require.NotNil(t, aggStatus.Err())
	assert.Contains(t, aggStatus.Err().Error(), "connection refused")

	// Verify start_time was parsed
	require.NotNil(t, ss.StartTimestamp)

	// Verify extensions component
	require.Contains(t, aggStatus.ComponentStatusMap, "extensions")
	extensions := aggStatus.ComponentStatusMap["extensions"]
	assert.Equal(t, componentstatus.StatusOK, extensions.Status())
	assert.Len(t, extensions.ComponentStatusMap, 2)
	assert.Contains(t, extensions.ComponentStatusMap, "extension:beatsauth/_agent-component/default")
	assert.Contains(t, extensions.ComponentStatusMap, "extension:healthcheckv2/test-id")

	// Verify pipeline component
	pipelineKey := "pipeline:logs/_agent-component/system/metrics-default"
	require.Contains(t, aggStatus.ComponentStatusMap, pipelineKey)
	pipeline := aggStatus.ComponentStatusMap[pipelineKey]
	assert.Equal(t, componentstatus.StatusRecoverableError, pipeline.Status())

	// Verify nested pipeline components
	assert.Len(t, pipeline.ComponentStatusMap, 2)
	exporterKey := "exporter:elasticsearch/_agent-component/default"
	receiverKey := "receiver:metricbeatreceiver/_agent-component/system/metrics-default"
	assert.Contains(t, pipeline.ComponentStatusMap, exporterKey)
	assert.Contains(t, pipeline.ComponentStatusMap, receiverKey)

	// Verify receiver has attributes with inputs
	receiver := pipeline.ComponentStatusMap[receiverKey]
	assert.Equal(t, componentstatus.StatusRecoverableError, receiver.Status())

	// The attributes should be accessible via the original SerializableStatus
	receiverSS := ss.ComponentStatuses[pipelineKey].ComponentStatuses[receiverKey]
	require.NotNil(t, receiverSS.Attributes)
	inputs, ok := receiverSS.Attributes["inputs"]
	require.True(t, ok, "receiver should have inputs in attributes")
	inputsMap, ok := inputs.(map[string]any)
	require.True(t, ok)
	assert.Len(t, inputsMap, 2)
}

func TestFromSerializableEvent(t *testing.T) {
	tests := []struct {
		name             string
		event            *SerializableEvent
		expectedStatus   componentstatus.Status
		expectedErr      string
		checkAttrs       bool
		expectedParseErr string
	}{
		{
			name:           "nil event returns nil",
			event:          nil,
			expectedStatus: componentstatus.StatusNone,
		},
		{
			name: "StatusOK",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusOK",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusOK,
		},
		{
			name: "StatusRecoverableError with error",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusRecoverableError",
				Error:        "recoverable error message",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusRecoverableError,
			expectedErr:    "recoverable error message",
		},
		{
			name: "StatusPermanentError",
			event: &SerializableEvent{
				Healthy:      false,
				StatusString: "StatusPermanentError",
				Error:        "permanent error",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusPermanentError,
			expectedErr:    "permanent error",
		},
		{
			name: "StatusFatalError",
			event: &SerializableEvent{
				Healthy:      false,
				StatusString: "StatusFatalError",
				Error:        "fatal error",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusFatalError,
			expectedErr:    "fatal error",
		},
		{
			name: "StatusStarting",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusStarting",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusStarting,
		},
		{
			name: "StatusStopping",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusStopping",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusStopping,
		},
		{
			name: "StatusStopped",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusStopped",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusStopped,
		},
		{
			name: "unknown status defaults to StatusNone",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "InvalidStatus",
				Timestamp:    time.Now(),
			},
			expectedStatus: componentstatus.StatusNone,
		},
		{
			name: "event with valid attributes",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusOK",
				Timestamp:    time.Now(),
				Attributes: map[string]any{
					"key1": "value1",
					"key2": 42,
					"nested": map[string]any{
						"inner": "data",
					},
				},
			},
			expectedStatus: componentstatus.StatusOK,
			checkAttrs:     true,
		},
		{
			name: "event with invalid attributes",
			event: &SerializableEvent{
				Healthy:      true,
				StatusString: "StatusOK",
				Timestamp:    time.Now(),
				Attributes: map[string]any{
					"invalid": make(chan int),
				},
			},
			expectedStatus:   componentstatus.StatusOK,
			expectedParseErr: "error parsing event attributes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := FromSerializableEvent(tt.event)
			if tt.expectedParseErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedParseErr)
				return
			}
			require.NoError(t, err)

			if tt.event == nil {
				assert.Nil(t, event)
				return
			}

			require.NotNil(t, event)
			assert.Equal(t, tt.expectedStatus, event.Status())

			if tt.expectedErr != "" {
				require.NotNil(t, event.Err())
				assert.Equal(t, tt.expectedErr, event.Err().Error())
			} else {
				assert.Nil(t, event.Err())
			}

			if tt.checkAttrs {
				attrs := event.Attributes()
				assert.Equal(t, 3, attrs.Len())
				val, ok := attrs.Get("key1")
				require.True(t, ok)
				assert.Equal(t, "value1", val.Str())
			}
		})
	}
}

func TestFromSerializableStatus(t *testing.T) {
	timestamp := time.Now()

	tests := []struct {
		name    string
		input   *SerializableStatus
		checkFn func(t *testing.T, result *status.AggregateStatus)
	}{
		{
			name: "simple status",
			input: &SerializableStatus{
				SerializableEvent: &SerializableEvent{
					Healthy:      true,
					StatusString: "StatusOK",
					Timestamp:    timestamp,
				},
			},
			checkFn: func(t *testing.T, result *status.AggregateStatus) {
				assert.Equal(t, componentstatus.StatusOK, result.Status())
				assert.Nil(t, result.Err())
				assert.Empty(t, result.ComponentStatusMap)
			},
		},
		{
			name: "status with error",
			input: &SerializableStatus{
				SerializableEvent: &SerializableEvent{
					Healthy:      false,
					StatusString: "StatusPermanentError",
					Error:        "test error",
					Timestamp:    timestamp,
				},
			},
			checkFn: func(t *testing.T, result *status.AggregateStatus) {
				assert.Equal(t, componentstatus.StatusPermanentError, result.Status())
				require.NotNil(t, result.Err())
				assert.Equal(t, "test error", result.Err().Error())
			},
		},
		{
			name: "status with components",
			input: &SerializableStatus{
				SerializableEvent: &SerializableEvent{
					Healthy:      true,
					StatusString: "StatusOK",
					Timestamp:    timestamp,
				},
				ComponentStatuses: map[string]*SerializableStatus{
					"component1": {
						SerializableEvent: &SerializableEvent{
							Healthy:      true,
							StatusString: "StatusOK",
							Timestamp:    timestamp,
						},
					},
					"component2": {
						SerializableEvent: &SerializableEvent{
							Healthy:      false,
							StatusString: "StatusRecoverableError",
							Error:        "component error",
							Timestamp:    timestamp,
						},
					},
				},
			},
			checkFn: func(t *testing.T, result *status.AggregateStatus) {
				assert.Equal(t, componentstatus.StatusOK, result.Status())
				assert.Len(t, result.ComponentStatusMap, 2)

				comp1 := result.ComponentStatusMap["component1"]
				require.NotNil(t, comp1)
				assert.Equal(t, componentstatus.StatusOK, comp1.Status())

				comp2 := result.ComponentStatusMap["component2"]
				require.NotNil(t, comp2)
				assert.Equal(t, componentstatus.StatusRecoverableError, comp2.Status())
				require.NotNil(t, comp2.Err())
				assert.Equal(t, "component error", comp2.Err().Error())
			},
		},
		{
			name: "deeply nested components",
			input: &SerializableStatus{
				SerializableEvent: &SerializableEvent{
					Healthy:      true,
					StatusString: "StatusOK",
					Timestamp:    timestamp,
				},
				ComponentStatuses: map[string]*SerializableStatus{
					"level1": {
						SerializableEvent: &SerializableEvent{
							Healthy:      true,
							StatusString: "StatusOK",
							Timestamp:    timestamp,
						},
						ComponentStatuses: map[string]*SerializableStatus{
							"level2": {
								SerializableEvent: &SerializableEvent{
									Healthy:      true,
									StatusString: "StatusOK",
									Timestamp:    timestamp,
								},
								ComponentStatuses: map[string]*SerializableStatus{
									"level3": {
										SerializableEvent: &SerializableEvent{
											Healthy:      false,
											StatusString: "StatusFatalError",
											Error:        "deep error",
											Timestamp:    timestamp,
										},
									},
								},
							},
						},
					},
				},
			},
			checkFn: func(t *testing.T, result *status.AggregateStatus) {
				level1 := result.ComponentStatusMap["level1"]
				require.NotNil(t, level1)

				level2 := level1.ComponentStatusMap["level2"]
				require.NotNil(t, level2)

				level3 := level2.ComponentStatusMap["level3"]
				require.NotNil(t, level3)
				assert.Equal(t, componentstatus.StatusFatalError, level3.Status())
				require.NotNil(t, level3.Err())
				assert.Equal(t, "deep error", level3.Err().Error())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FromSerializableStatus(tt.input)
			require.NoError(t, err)
			require.NotNil(t, result)
			tt.checkFn(t, result)
		})
	}
}

func TestAggregateStatusHelper(t *testing.T) {
	t.Run("creates status without error", func(t *testing.T) {
		result := AggregateStatus(componentstatus.StatusOK, nil)
		require.NotNil(t, result)
		assert.Equal(t, componentstatus.StatusOK, result.Status())
		assert.Nil(t, result.Err())
		assert.NotNil(t, result.ComponentStatusMap)
		assert.Empty(t, result.ComponentStatusMap)
		assert.NotNil(t, result.Attributes())
		assert.Empty(t, result.Attributes().AsRaw())
	})

	t.Run("creates status with error", func(t *testing.T) {
		err := errors.New("test error")
		result := AggregateStatus(componentstatus.StatusRecoverableError, err)
		require.NotNil(t, result)
		assert.Equal(t, componentstatus.StatusRecoverableError, result.Status())
		require.NotNil(t, result.Err())
		assert.Equal(t, "test error", result.Err().Error())
	})

	t.Run("sets timestamp", func(t *testing.T) {
		before := time.Now()
		result := AggregateStatus(componentstatus.StatusOK, nil)
		after := time.Now()

		timestamp := result.Timestamp()
		assert.True(t, timestamp.After(before) || timestamp.Equal(before))
		assert.True(t, timestamp.Before(after) || timestamp.Equal(after))
	})
}
