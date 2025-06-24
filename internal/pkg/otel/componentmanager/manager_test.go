// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package componentmanager

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/version"

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
}

func TestOtelComponentManager_buildMergedConfig(t *testing.T) {
	// Common parameters used across all test cases
	commonAgentInfo := &info.AgentInfo{}
	commonBeatMonitoringConfigGetter := mockBeatMonitoringConfigGetter
	testComp := testComponent("test-component")

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
			collectorCfg: confmap.NewFromStringMap(map[string]any{"receivers": map[string]any{"nop": map[string]any{}}}),
			components:   nil,
			expectedKeys: []string{"receivers"},
		},
		{
			name:         "components only",
			collectorCfg: nil,
			components:   []component.Component{testComp},
			expectedKeys: []string{"receivers", "exporters", "service"},
		},
		{
			name:         "both collector config and components",
			collectorCfg: confmap.NewFromStringMap(map[string]any{"processors": map[string]any{"batch": map[string]any{}}}),
			components:   []component.Component{testComp},
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

			result, err := mgr.buildMergedConfig()

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
	testComp := testComponent("test-component")
	var updatedConfig *confmap.Conf
	fakeManager := &fakeOTelManager{
		updateCallback: func(cfg *confmap.Conf) error {
			updatedConfig = cfg
			return nil
		},
	}
	t.Run("successful update with empty model", func(t *testing.T) {
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
		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		// Use a valid component that will generate otel config
		model := component.Model{Components: []component.Component{testComp}}

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
	var updatedConfig *confmap.Conf
	fakeManager := &fakeOTelManager{
		updateCallback: func(cfg *confmap.Conf) error {
			updatedConfig = cfg
			return nil
		},
	}
	t.Run("successful update with nil collector config", func(t *testing.T) {
		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		err := mgr.handleCollectorUpdate(nil)

		assert.NoError(t, err)
		assert.Nil(t, mgr.collectorCfg)
		assert.Nil(t, mgr.MergedOtelConfig())
		// Verify that Update was called with nil config (no collector config should result in nil config)
		assert.Nil(t, updatedConfig)
	})

	t.Run("successful update with collector config", func(t *testing.T) {
		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		collectorConfig := confmap.NewFromStringMap(map[string]any{
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
		assert.Equal(t, collectorConfig, mgr.MergedOtelConfig())
		// Verify that Update was called with the collector configuration
		assert.NotNil(t, updatedConfig)
		// Verify that the configuration contains expected collector sections
		assert.True(t, updatedConfig.IsSet("receivers"), "Expected receivers section in config")
		assert.True(t, updatedConfig.IsSet("processors"), "Expected processors section in config")
	})

	t.Run("successful update with both collector config and existing components", func(t *testing.T) {
		mgr := &OtelComponentManager{
			logger:                     newTestLogger(),
			otelManager:                fakeManager,
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
			// Set existing components to test merging
			components: []component.Component{
				testComponent("test-component")},
		}

		collectorConfig := confmap.NewFromStringMap(map[string]any{
			"processors": map[string]any{
				"batch": map[string]any{},
			},
		})

		err := mgr.handleCollectorUpdate(collectorConfig)

		assert.NoError(t, err)
		assert.Equal(t, collectorConfig, mgr.collectorCfg)
		assert.Equal(t, updatedConfig, mgr.MergedOtelConfig())
		// Verify that the configuration contains both collector and component sections
		assert.True(t, updatedConfig.IsSet("receivers"), "Expected receivers section from components")
		assert.True(t, updatedConfig.IsSet("exporters"), "Expected exporters section from components")
		assert.True(t, updatedConfig.IsSet("service"), "Expected service section from components")
		assert.True(t, updatedConfig.IsSet("processors"), "Expected processors section from collector config")
	})
}

func TestOtelComponentManager_handleOtelStatusUpdate(t *testing.T) {
	// Common test component used across test cases
	testComp := testComponent("test-component")

	tests := []struct {
		name                    string
		components              []component.Component
		inputStatus             *status.AggregateStatus
		expectedErrorString     string
		expectedCollectorStatus *status.AggregateStatus
		expectedComponentStates []runtime.ComponentComponentState
	}{
		{
			name:       "successful status update with component states",
			components: []component.Component{testComp},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					// This represents a pipeline for our component (with OtelNamePrefix)
					"pipeline:logs/_agent-component/test-component": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"receiver:filebeat/_agent-component/test-component": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"exporter:elasticsearch/_agent-component/test-component": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
					},
					// This represents a regular collector pipeline (should remain after cleaning)
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expectedCollectorStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
				ComponentStatusMap: map[string]*status.AggregateStatus{
					// This represents a regular collector pipeline (should remain after cleaning)
					"pipeline:logs": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
					},
				},
			},
			expectedComponentStates: []runtime.ComponentComponentState{
				{
					Component: testComp,
					State: runtime.ComponentState{
						State:   client.UnitStateHealthy,
						Message: "HEALTHY",
						Units: map[runtime.ComponentUnitKey]runtime.ComponentUnitState{
							runtime.ComponentUnitKey{
								UnitID:   "filestream-unit",
								UnitType: client.UnitTypeInput,
							}: {
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
							runtime.ComponentUnitKey{
								UnitID:   "filestream-default",
								UnitType: client.UnitTypeOutput,
							}: {
								State:   client.UnitStateHealthy,
								Message: "Healthy",
							},
						},
						VersionInfo: runtime.ComponentVersionInfo{
							Name: translate.OtelComponentName,
							Meta: map[string]string{
								"build_time": version.BuildTime().String(),
								"commit":     version.Commit(),
							},
							BuildHash: version.Commit(),
						},
					},
				},
			},
		},
		{
			name:                    "handles nil otel status",
			components:              []component.Component{},
			inputStatus:             nil,
			expectedErrorString:     "otel status is nil",
			expectedCollectorStatus: nil,
			expectedComponentStates: nil,
		},
		{
			name:       "handles empty components list",
			components: []component.Component{},
			inputStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expectedErrorString: "",
			expectedCollectorStatus: &status.AggregateStatus{
				Event: componentstatus.NewEvent(componentstatus.StatusOK),
			},
			expectedComponentStates: nil,
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
			if tt.expectedErrorString != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErrorString)
				return
			}

			require.NoError(t, err)

			// Compare component states
			assert.Equal(t, tt.expectedComponentStates, componentStates)

			// Compare collector status
			assertOtelStatusesEqualIgnoringTimestamps(t, tt.expectedCollectorStatus, mgr.currentCollectorStatus)
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
	return f.errChan
}

func (f *fakeOTelManager) Update(cfg *confmap.Conf) {
	f.result = nil
	if f.updateCallback != nil {
		f.result = f.updateCallback(cfg)
	}
	if f.errChan != nil {
		// If a reporting channel is set, send the result to it
		// Drain the channel if necessary, we only care about the latest error
		select {
		case <-f.errChan:
		default:
		}
		f.errChan <- f.result
	}
}

func (f *fakeOTelManager) Watch() <-chan *status.AggregateStatus {
	return f.statusChan
}

// TestOtelComponentManagerEndToEnd tests the full lifecycle of the OtelComponentManager
// including configuration updates, status updates, and error handling.
func TestOtelComponentManagerEndToEnd(t *testing.T) {
	// Setup test logger and dependencies
	testLogger, _ := loggertest.New("test")
	agentInfo := &info.AgentInfo{}
	beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter

	otelStatusChan := make(chan *status.AggregateStatus, 1)
	otelErrChan := make(chan error, 1)
	otelConfigChan := make(chan *confmap.Conf, 1)
	otelManager := &fakeOTelManager{
		updateCallback: func(cfg *confmap.Conf) error {
			otelConfigChan <- cfg
			return nil
		},
		statusChan: otelStatusChan,
		errChan:    otelErrChan,
	}

	// Create manager with test dependencies
	mgr := NewOtelComponentManager(testLogger, otelManager, agentInfo, beatMonitoringConfigGetter)
	require.NotNil(t, mgr)

	// Start manager in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*1)
	defer cancel()

	go func() {
		err := mgr.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	}()

	collectorCfg := confmap.NewFromStringMap(map[string]interface{}{
		"receivers": map[string]interface{}{
			"nop": map[string]interface{}{},
		},
		"exporters": map[string]interface{}{"nop": map[string]interface{}{}},
		"service": map[string]interface{}{
			"pipelines": map[string]interface{}{
				"metrics": map[string]interface{}{
					"receivers": []string{"nop"},
					"exporters": []string{"nop"},
				},
			},
		},
	})

	testComp := testComponent("test")

	componentModel := component.Model{
		Components: []component.Component{
			testComp,
		},
	}

	t.Run("collector config is passed down to the otel manager", func(t *testing.T) {
		mgr.UpdateCollector(collectorCfg)
		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
		require.NoError(t, err)
		assert.Equal(t, collectorCfg, cfg)
	})

	t.Run("collector status is passed up to the component manager", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
		}

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case otelStatusChan <- otelStatus:
		}

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		assert.Equal(t, otelStatus, collectorStatus)
	})

	t.Run("component config is passed down to the otel manager", func(t *testing.T) {
		mgr.UpdateComponents(componentModel)
		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
		require.NoError(t, err)
		require.NotNil(t, cfg)
		receivers, err := cfg.Sub("receivers")
		require.NoError(t, err)
		require.NotNil(t, receivers)
		assert.True(t, receivers.IsSet("nop"))
		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))
	})

	t.Run("empty collector config leaves the component config running", func(t *testing.T) {
		mgr.UpdateCollector(nil)
		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
		require.NotNil(t, cfg)
		require.NoError(t, err)
		receivers, err := cfg.Sub("receivers")
		require.NoError(t, err)
		require.NotNil(t, receivers)
		assert.False(t, receivers.IsSet("nop"))
		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))
	})

	t.Run("collector status with components is passed up to the component manager", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
			ComponentStatusMap: map[string]*status.AggregateStatus{
				// This represents a pipeline for our component (with OtelNamePrefix)
				"pipeline:logs/_agent-component/test": {
					Event: componentstatus.NewEvent(componentstatus.StatusOK),
					ComponentStatusMap: map[string]*status.AggregateStatus{
						"receiver:filebeatreceiver/_agent-component/test": {
							Event: componentstatus.NewEvent(componentstatus.StatusOK),
						},
						"exporter:elasticsearch/_agent-component/test": {
							Event: componentstatus.NewEvent(componentstatus.StatusOK),
						},
					},
				},
			},
		}

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case otelStatusChan <- otelStatus:
		}

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		assert.Len(t, collectorStatus.ComponentStatusMap, 0)

		componentState, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(t, err)
		assert.Equal(t, componentState.Component, testComp)
	})

	t.Run("collector error is passed up to the component manager", func(t *testing.T) {
		collectorErr := errors.New("collector error")

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case otelErrChan <- collectorErr:
		}

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.Nil(t, collectorStatus)
		assert.Equal(t, err, collectorErr)
	})
}

func testComponent(componentId string) component.Component {
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

	return component.Component{
		ID:             componentId,
		RuntimeManager: component.OtelRuntimeManager,
		InputType:      "filestream",
		OutputType:     "elasticsearch",
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
				ID:     "filestream-unit",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(fileStreamConfig),
			},
			{
				ID:     "filestream-default",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(esOutputConfig),
			},
		},
	}
}

func getFromChannelOrErrorWithContext[T any](t *testing.T, ctx context.Context, ch <-chan T, errCh <-chan error) (T, error) {
	t.Helper()
	var result T
	var err error
	for err == nil {
		select {
		case result = <-ch:
			return result, nil
		case err = <-errCh:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	return result, err
}

func assertOtelStatusesEqualIgnoringTimestamps(t require.TestingT, a, b *status.AggregateStatus) bool {
	if a == nil || b == nil {
		return assert.Equal(t, a, b)
	}

	if !assert.Equal(t, a.Status(), b.Status()) {
		return false
	}

	if !assert.Equal(t, len(a.ComponentStatusMap), len(b.ComponentStatusMap)) {
		return false
	}

	for k, v := range a.ComponentStatusMap {
		if !assertOtelStatusesEqualIgnoringTimestamps(t, v, b.ComponentStatusMap[k]) {
			return false
		}
	}

	return true
}
