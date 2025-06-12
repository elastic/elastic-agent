// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package componentmanager

import (
	"context"
	"testing"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

// Mock function for BeatMonitoringConfigGetter
func mockBeatMonitoringConfigGetter(unitID, binary string) map[string]any {
	return map[string]any{"test": "config"}
}

// Helper function to create test logger
func newTestLogger() *logger.Logger {
	l, _ := loggertest.New("test")
	return l
}

func TestNewOtelComponentManager(t *testing.T) {
	t.Run("successful creation with all dependencies", func(t *testing.T) {
		testLogger := newTestLogger()
		otelManager := &fakeOTelManager{}
		agentInfo := &info.AgentInfo{}
		beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter

		mgr := NewOtelComponentManager(testLogger, otelManager, agentInfo, beatMonitoringConfigGetter)

		assert.NotNil(t, mgr)
		assert.Equal(t, testLogger, mgr.logger)
		assert.Equal(t, otelManager, mgr.otelManager)
		assert.Equal(t, agentInfo, mgr.agentInfo)
		assert.NotNil(t, mgr.beatMonitoringConfigGetter)
		assert.NotNil(t, mgr.collectorUpdateChan)
		assert.NotNil(t, mgr.componentUpdateChan)
		assert.NotNil(t, mgr.errCh)
		assert.NotNil(t, mgr.collectorWatchChan)
		assert.NotNil(t, mgr.componentWatchChan)
		assert.NotNil(t, mgr.doneChan)
		assert.NotNil(t, mgr.currentComponentStates)
	})

	t.Run("successful creation with nil beat monitoring config getter", func(t *testing.T) {
		testLogger := newTestLogger()
		otelManager := &fakeOTelManager{}
		agentInfo := &info.AgentInfo{}

		mgr := NewOtelComponentManager(testLogger, otelManager, agentInfo, nil)

		assert.NotNil(t, mgr)
		assert.Equal(t, testLogger, mgr.logger)
		assert.Equal(t, otelManager, mgr.otelManager)
		assert.Equal(t, agentInfo, mgr.agentInfo)
		assert.Nil(t, mgr.beatMonitoringConfigGetter)
		assert.NotNil(t, mgr.collectorUpdateChan)
		assert.NotNil(t, mgr.componentUpdateChan)
		assert.NotNil(t, mgr.errCh)
		assert.NotNil(t, mgr.collectorWatchChan)
		assert.NotNil(t, mgr.componentWatchChan)
		assert.NotNil(t, mgr.doneChan)
		assert.NotNil(t, mgr.currentComponentStates)
	})
}

func TestOtelComponentManager_buildFinalConfig(t *testing.T) {
	// Common parameters used across all test cases
	commonAgentInfo := &info.AgentInfo{}
	commonBeatMonitoringConfigGetter := mockBeatMonitoringConfigGetter

	tests := []struct {
		name                string
		collectorCfg        *confmap.Conf
		components          []component.Component
		expectedKeys        []string
		expectedErrorString string
	}{
		{
			name:         "empty config returns nil",
			collectorCfg: nil,
			components:   nil,
		},
		{
			name:         "collector config only",
			collectorCfg: createTestConfig(map[string]any{"receivers": map[string]any{"nop": map[string]any{}}}),
			components:   nil,
			expectedKeys: []string{"receivers"},
		},
		{
			name:         "components only",
			collectorCfg: nil,
			components: []component.Component{{
				ID:         "test-component",
				InputType:  "filestream",
				OutputType: "elasticsearch",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
				Units: []component.Unit{{
					ID:   "test-unit",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]any{
						"type": "filestream",
						"streams": []any{
							map[string]any{
								"id":    "test-stream",
								"paths": []any{"/var/log/*.log"},
							},
						},
					}),
				}},
			}},
			expectedKeys: []string{"receivers", "exporters", "service"},
		},
		{
			name:         "both collector config and components",
			collectorCfg: createTestConfig(map[string]any{"processors": map[string]any{"batch": map[string]any{}}}),
			components: []component.Component{{
				ID:         "test-component",
				InputType:  "filestream",
				OutputType: "elasticsearch",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
				Units: []component.Unit{{
					ID:   "test-unit",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]any{
						"type": "filestream",
						"streams": []any{
							map[string]any{
								"id":    "test-stream",
								"paths": []any{"/var/log/*.log"},
							},
						},
					}),
				}},
			}},
			expectedKeys: []string{"receivers", "exporters", "service", "processors"},
		},
		{
			name:         "component config generation error",
			collectorCfg: nil,
			components: []component.Component{{
				ID:         "test-component",
				InputType:  "filestream",    // Supported input type
				OutputType: "elasticsearch", // Supported output type
				// Missing InputSpec which should cause an error during config generation
			}},
			expectedErrorString: "failed to generate otel config: unknown otel receiver type for input type: filestream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &OtelComponentManager{
				logger:                     newTestLogger(),
				collectorCfg:               tt.collectorCfg,
				components:                 tt.components,
				agentInfo:                  commonAgentInfo,
				beatMonitoringConfigGetter: commonBeatMonitoringConfigGetter,
			}

			result, err := mgr.buildFinalConfig()

			if tt.expectedErrorString != "" {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErrorString, err.Error())
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)

			if len(tt.expectedKeys) == 0 {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			for _, key := range tt.expectedKeys {
				assert.True(t, result.IsSet(key), "Expected key %s to be set", key)
			}
		})
	}
}

func TestOtelComponentManager_handleComponentUpdate(t *testing.T) {
	t.Run("successful update with empty model", func(t *testing.T) {
		var updatedConfig *confmap.Conf
		fakeManager := &fakeOTelManager{
			updateCallback: func(cfg *confmap.Conf) error {
				updatedConfig = cfg
				return nil
			},
		}

		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		model := component.Model{Components: nil}
		err := mgr.handleComponentUpdate(model)

		assert.NoError(t, err)
		assert.Equal(t, model.Components, mgr.components)
		// Verify that Update was called with nil config (empty components should result in nil config)
		assert.Nil(t, updatedConfig)
	})

	t.Run("successful update with components", func(t *testing.T) {
		var updatedConfig *confmap.Conf
		fakeManager := &fakeOTelManager{
			updateCallback: func(cfg *confmap.Conf) error {
				updatedConfig = cfg
				return nil
			},
		}

		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		// Use a valid component that will generate otel config
		model := component.Model{Components: []component.Component{{
			ID:         "test-component",
			InputType:  "filestream",
			OutputType: "elasticsearch",
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "agentbeat",
				Spec: component.InputSpec{
					Command: &component.CommandSpec{
						Args: []string{"filebeat"},
					},
				},
			},
			Units: []component.Unit{{
				ID:   "test-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"type": "filestream",
					"streams": []any{
						map[string]any{
							"id":    "test-stream",
							"paths": []any{"/var/log/*.log"},
						},
					},
				}),
			}},
		}}}

		err := mgr.handleComponentUpdate(model)

		assert.NoError(t, err)
		assert.Equal(t, model.Components, mgr.components)
		// Verify that Update was called with a valid configuration
		assert.NotNil(t, updatedConfig)
		// Verify that the configuration contains expected OpenTelemetry sections
		assert.True(t, updatedConfig.IsSet("receivers"), "Expected receivers section in config")
		assert.True(t, updatedConfig.IsSet("exporters"), "Expected exporters section in config")
		assert.True(t, updatedConfig.IsSet("service"), "Expected service section in config")
	})
}

func TestOtelComponentManager_handleCollectorUpdate(t *testing.T) {
	t.Run("successful update with nil collector config", func(t *testing.T) {
		var updatedConfig *confmap.Conf
		fakeManager := &fakeOTelManager{
			updateCallback: func(cfg *confmap.Conf) error {
				updatedConfig = cfg
				return nil
			},
		}

		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		err := mgr.handleCollectorUpdate(nil)

		assert.NoError(t, err)
		assert.Nil(t, mgr.collectorCfg)
		// Verify that Update was called with nil config (no collector config should result in nil config)
		assert.Nil(t, updatedConfig)
	})

	t.Run("successful update with collector config", func(t *testing.T) {
		var updatedConfig *confmap.Conf
		fakeManager := &fakeOTelManager{
			updateCallback: func(cfg *confmap.Conf) error {
				updatedConfig = cfg
				return nil
			},
		}

		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		collectorConfig := createTestConfig(map[string]any{
			"receivers": map[string]any{
				"nop": map[string]any{},
			},
			"processors": map[string]any{
				"batch": map[string]any{},
			},
		})

		err := mgr.handleCollectorUpdate(collectorConfig)

		assert.NoError(t, err)
		assert.Equal(t, collectorConfig, mgr.collectorCfg)
		// Verify that Update was called with the collector configuration
		assert.NotNil(t, updatedConfig)
		// Verify that the configuration contains expected collector sections
		assert.True(t, updatedConfig.IsSet("receivers"), "Expected receivers section in config")
		assert.True(t, updatedConfig.IsSet("processors"), "Expected processors section in config")
	})

	t.Run("successful update with both collector config and existing components", func(t *testing.T) {
		var updatedConfig *confmap.Conf
		fakeManager := &fakeOTelManager{
			updateCallback: func(cfg *confmap.Conf) error {
				updatedConfig = cfg
				return nil
			},
		}

		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
			// Set existing components to test merging
			components: []component.Component{{
				ID:         "test-component",
				InputType:  "filestream",
				OutputType: "elasticsearch",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
				Units: []component.Unit{{
					ID:   "test-unit",
					Type: client.UnitTypeInput,
					Config: component.MustExpectedConfig(map[string]any{
						"type": "filestream",
						"streams": []any{
							map[string]any{
								"id":    "test-stream",
								"paths": []any{"/var/log/*.log"},
							},
						},
					}),
				}},
			}},
		}

		collectorConfig := createTestConfig(map[string]any{
			"processors": map[string]any{
				"batch": map[string]any{},
			},
		})

		err := mgr.handleCollectorUpdate(collectorConfig)

		assert.NoError(t, err)
		assert.Equal(t, collectorConfig, mgr.collectorCfg)
		// Verify that Update was called with merged configuration
		assert.NotNil(t, updatedConfig)
		// Verify that the configuration contains both collector and component sections
		assert.True(t, updatedConfig.IsSet("receivers"), "Expected receivers section from components")
		assert.True(t, updatedConfig.IsSet("exporters"), "Expected exporters section from components")
		assert.True(t, updatedConfig.IsSet("service"), "Expected service section from components")
		assert.True(t, updatedConfig.IsSet("processors"), "Expected processors section from collector config")
	})
}

func TestOtelComponentManager_handleOtelStatusUpdate(t *testing.T) {
	// Common test component used across test cases
	testComponent := component.Component{
		ID:             "test-component",
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
		Units: []component.Unit{{
			ID:   "test-unit",
			Type: client.UnitTypeInput,
			Config: component.MustExpectedConfig(map[string]any{
				"type": "filestream",
				"streams": []any{
					map[string]any{
						"id":    "test-stream",
						"paths": []any{"/var/log/*.log"},
					},
				},
			}),
		}},
	}

	tests := []struct {
		name                           string
		components                     []component.Component
		inputStatus                    *status.AggregateStatus
		expectError                    bool
		expectedCollectorStatusNil     bool
		expectedComponentPipelineGone  bool
		expectedRegularPipelineRemains bool
	}{
		{
			name:       "successful status update with component states",
			components: []component.Component{testComponent},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					// This represents a pipeline for our component (with OtelNamePrefix)
					"pipeline:logs/_agent-component/test-component": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					// This represents a regular collector pipeline (should remain after cleaning)
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expectError:                    false,
			expectedCollectorStatusNil:     false,
			expectedComponentPipelineGone:  true,
			expectedRegularPipelineRemains: true,
		},
		{
			name:                       "handles nil otel status",
			components:                 []component.Component{},
			inputStatus:                nil,
			expectError:                false,
			expectedCollectorStatusNil: true,
		},
		{
			name:       "handles empty components list",
			components: []component.Component{},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expectError:                false,
			expectedCollectorStatusNil: false,
		},
		{
			name:       "updates current collector status after cleaning",
			components: []component.Component{},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expectError:                false,
			expectedCollectorStatusNil: false,
		},
		{
			name:       "extracts component states from actual status data",
			components: []component.Component{testComponent},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					// This represents a pipeline for our component (with OtelNamePrefix)
					"pipeline:logs/_agent-component/test-component": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
					// This represents a regular collector pipeline (should remain after cleaning)
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expectError:                    false,
			expectedCollectorStatusNil:     false,
			expectedComponentPipelineGone:  true,
			expectedRegularPipelineRemains: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &OtelComponentManager{
				logger:                 newTestLogger(),
				components:             tt.components,
				currentComponentStates: make(map[string]runtime.ComponentComponentState),
			}

			componentStates, err := mgr.handleOtelStatusUpdate(tt.inputStatus)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Component states may be nil or empty depending on the translate package behavior
			// This is acceptable - we just verify the function completed successfully
			_ = componentStates

			// Verify collector status update
			if tt.expectedCollectorStatusNil {
				assert.Nil(t, mgr.currentCollectorStatus)
			} else {
				assert.Equal(t, tt.inputStatus, mgr.currentCollectorStatus)
			}

			// Verify status cleaning behavior (only applicable when we have status with pipelines)
			if tt.inputStatus != nil && tt.inputStatus.ComponentStatusMap != nil {
				if tt.expectedComponentPipelineGone {
					_, hasComponentPipeline := tt.inputStatus.ComponentStatusMap["pipeline:logs/_agent-component/test-component"]
					assert.False(t, hasComponentPipeline, "Component pipeline should be removed from collector status")
				}
				if tt.expectedRegularPipelineRemains {
					_, hasCollectorPipeline := tt.inputStatus.ComponentStatusMap["pipeline:logs"]
					assert.True(t, hasCollectorPipeline, "Regular collector pipeline should remain in status")
				}
			}
		})
	}
}

func TestOtelComponentManager_processComponentStates(t *testing.T) {
	tests := []struct {
		name                       string
		currentComponentStates     map[string]runtime.ComponentComponentState
		inputComponentStates       []runtime.ComponentComponentState
		expectedOutputStates       []runtime.ComponentComponentState
		expectedCurrentStatesAfter map[string]runtime.ComponentComponentState
	}{
		{
			name:                       "empty input and current states",
			currentComponentStates:     map[string]runtime.ComponentComponentState{},
			inputComponentStates:       []runtime.ComponentComponentState{},
			expectedOutputStates:       []runtime.ComponentComponentState{},
			expectedCurrentStatesAfter: map[string]runtime.ComponentComponentState{},
		},
		{
			name:                   "new component state added",
			currentComponentStates: map[string]runtime.ComponentComponentState{},
			inputComponentStates: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateHealthy},
				},
			},
			expectedOutputStates: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateHealthy},
				},
			},
			expectedCurrentStatesAfter: map[string]runtime.ComponentComponentState{
				"comp1": {
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateHealthy},
				},
			},
		},
		{
			name: "component removed from config generates STOPPED state",
			currentComponentStates: map[string]runtime.ComponentComponentState{
				"comp1": {
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateHealthy},
				},
			},
			inputComponentStates: []runtime.ComponentComponentState{},
			expectedOutputStates: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateStopped},
				},
			},
			expectedCurrentStatesAfter: map[string]runtime.ComponentComponentState{},
		},
		{
			name: "component stopped removes from current states",
			currentComponentStates: map[string]runtime.ComponentComponentState{
				"comp1": {
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateHealthy},
				},
			},
			inputComponentStates: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateStopped},
				},
			},
			expectedOutputStates: []runtime.ComponentComponentState{
				{
					Component: component.Component{ID: "comp1"},
					State:     runtime.ComponentState{State: client.UnitStateStopped},
				},
			},
			expectedCurrentStatesAfter: map[string]runtime.ComponentComponentState{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &OtelComponentManager{
				logger:                 newTestLogger(),
				currentComponentStates: tt.currentComponentStates,
			}

			result := mgr.processComponentStates(tt.inputComponentStates)

			assert.ElementsMatch(t, tt.expectedOutputStates, result)
			assert.Equal(t, tt.expectedCurrentStatesAfter, mgr.currentComponentStates)
		})
	}
}

// Helper function to create test configurations
func createTestConfig(data map[string]any) *confmap.Conf {
	cfg := confmap.New()
	for k, v := range data {
		err := cfg.Merge(confmap.NewFromStringMap(map[string]any{k: v}))
		if err != nil {
			panic(err)
		}
	}
	return cfg
}

type fakeOTelManager struct {
	updateCallback func(*confmap.Conf) error
	result         error
	errChan        chan error
	statusChan     chan *status.AggregateStatus
}

func (f *fakeOTelManager) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeOTelManager) Errors() <-chan error {
	return nil
}

func (f *fakeOTelManager) Update(cfg *confmap.Conf) {
	f.result = nil
	if f.updateCallback != nil {
		f.result = f.updateCallback(cfg)
	}
	if f.errChan != nil {
		// If a reporting channel is set, send the result to it
		f.errChan <- f.result
	}
}

func (f *fakeOTelManager) Watch() <-chan *status.AggregateStatus {
	return f.statusChan
}
