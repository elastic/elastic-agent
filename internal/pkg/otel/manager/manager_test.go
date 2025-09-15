// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

<<<<<<< HEAD
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
=======
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
>>>>>>> 779fafdcd ([beatreceivers] Integrate beatsauthextension (#9257))

	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

var (
	testConfig = map[string]interface{}{
		"receivers": map[string]interface{}{
			"nop": map[string]interface{}{},
		},
		"processors": map[string]interface{}{
			"batch": map[string]interface{}{},
		},
		"exporters": map[string]interface{}{
			"nop": map[string]interface{}{},
		},
		"service": map[string]interface{}{
			"telemetry": map[string]interface{}{
				"metrics": map[string]interface{}{
					"level":   "none",
					"readers": []any{},
				},
			},
			"pipelines": map[string]interface{}{
				"traces": map[string]interface{}{
					"receivers":  []string{"nop"},
					"processors": []string{"batch"},
					"exporters":  []string{"nop"},
				},
				"metrics": map[string]interface{}{
					"receivers":  []string{"nop"},
					"processors": []string{"batch"},
					"exporters":  []string{"nop"},
				},
				"logs": map[string]interface{}{
					"receivers":  []string{"nop"},
					"processors": []string{"batch"},
					"exporters":  []string{"nop"},
				},
			},
		},
	}
)

func TestOTelManager_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := loggertest.New("otel")
	m := NewOTelManager(l)

	var errMx sync.Mutex
	var err error
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-m.Errors():
				if e != nil {
					// no error should be produced (any error is a failure)
					errMx.Lock()
					err = e
					errMx.Unlock()
				}
			}
		}
	}()
	getLatestErr := func() error {
		errMx.Lock()
		defer errMx.Unlock()
		return err
	}

	var latestMx sync.Mutex
	var latest *status.AggregateStatus
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-m.Watch():
				latestMx.Lock()
				latest = c
				latestMx.Unlock()
			}
		}
	}()
	getLatestStatus := func() *status.AggregateStatus {
		latestMx.Lock()
		defer latestMx.Unlock()
		return latest
	}

	var runWg sync.WaitGroup
	var runErr error
	runWg.Add(1)
	go func() {
		defer runWg.Done()
		runErr = m.Run(ctx)
	}()

	ensureHealthy := func() {
		if !assert.Eventuallyf(t, func() bool {
			err := getLatestErr()
			if err != nil {
				// return now (but not for the correct reasons)
				return true
			}
			latest := getLatestStatus()
			if latest == nil || latest.Status() != componentstatus.StatusOK {
				return false
			}
			return true
		}, 5*time.Minute, 1*time.Second, "otel collector never got healthy") {
			lastStatus := getLatestStatus()
			lastErr := getLatestErr()

			// never got healthy, stop the manager and wait for it to end
			cancel()
			runWg.Wait()

			// if a run error happened then report that
			if !errors.Is(runErr, context.Canceled) {
				t.Fatalf("otel manager never got healthy and the otel manager returned unexpected error: %v (latest status: %+v) (latest err: %v)", runErr, lastStatus, lastErr)
			}
			t.Fatalf("otel collector never got healthy: %s (latest err: %v)", statusToYaml(lastStatus), lastErr)
		}
		latestErr := getLatestErr()
		require.NoError(t, latestErr, "runtime errored")
	}

	ensureOff := func() {
		require.Eventuallyf(t, func() bool {
			err := getLatestErr()
			if err != nil {
				// return now (but not for the correct reasons)
				return true
			}
			latest := getLatestStatus()
			return latest == nil
		}, 5*time.Minute, 1*time.Second, "otel collector never stopped")
		latestErr := getLatestErr()
		require.NoError(t, latestErr, "runtime errored")
	}

	// ensure that it got healthy
	cfg := confmap.NewFromStringMap(testConfig)
	m.Update(cfg)
	ensureHealthy()

	// trigger update (no config compare is due externally to otel collector)
	m.Update(cfg)
	ensureHealthy()

	// no configuration should stop the runner
	m.Update(nil)
	ensureOff()

	cancel()
	runWg.Wait()
	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("otel manager returned unexpected error: %v", runErr)
	}
}

func TestOTelManager_ConfigError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := loggertest.New("otel")
	m := NewOTelManager(l)

	go func() {
		err := m.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled, "otel manager should be cancelled")
	}()

	// watch is synchronous, so we need to read from it to avoid blocking the manager
	go func() {
		for {
			select {
			case <-m.Watch():
			case <-ctx.Done():
				return
			}
		}
	}()

	// Errors channel is non-blocking, should be able to send an Update that causes an error multiple
	// times without it blocking on sending over the errCh.
	for range 3 {
		cfg := confmap.New() // invalid config
		m.Update(cfg)

		// delay between updates to ensure the collector will have to fail
		<-time.After(100 * time.Millisecond)
	}

	// because of the retry logic and timing we need to ensure
	// that this keeps retrying to see the error and only store
	// an actual error
	//
	// a nil error just means that the collector is trying to restart
	// which clears the error on the restart loop
	timeoutCh := time.After(time.Second * 5)
	var err error
outer:
	for {
		select {
		case e := <-m.Errors():
			if e != nil {
				err = e
				break outer
			}
		case <-timeoutCh:
			break outer
		}
	}
	assert.Error(t, err, "otel manager should have returned an error")
}

func statusToYaml(s *status.AggregateStatus) string {
	printable := toSerializableStatus(s)
	yamlBytes, _ := yaml.Marshal(printable)
	return string(yamlBytes)
}

type serializableStatus struct {
	Status             string
	Error              error
	Timestamp          time.Time
	ComponentStatusMap map[string]serializableStatus
}

// converts the status.AggregateStatus to a serializable form. The normal status is structured in a way where
// serialization based on reflection doesn't give the right result.
func toSerializableStatus(s *status.AggregateStatus) *serializableStatus {
	if s == nil {
		return nil
	}

	outputComponentStatusMap := make(map[string]serializableStatus, len(s.ComponentStatusMap))
	for k, v := range s.ComponentStatusMap {
		outputComponentStatusMap[k] = *toSerializableStatus(v)
	}
	outputStruct := &serializableStatus{
		Status:             s.Status().String(),
		Error:              s.Err(),
		Timestamp:          s.Timestamp(),
		ComponentStatusMap: outputComponentStatusMap,
	}
	return outputStruct
}
<<<<<<< HEAD
=======

// Mock function for BeatMonitoringConfigGetter
func mockBeatMonitoringConfigGetter(unitID, binary string) map[string]any {
	return map[string]any{"test": "config"}
}

// Helper function to create test logger
func newTestLogger() *logger.Logger {
	l, _ := loggertest.New("test")
	return l
}

func TestOTelManager_buildMergedConfig(t *testing.T) {
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
			name:         "nil config returns nil",
			collectorCfg: nil,
			components:   nil,
		},
		{
			name:         "empty config returns empty config",
			collectorCfg: nil,
			components:   nil,
			expectedKeys: []string{},
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
			cfgUpdate := configUpdate{
				collectorCfg: tt.collectorCfg,
				components:   tt.components,
			}
			result, err := buildMergedConfig(cfgUpdate, commonAgentInfo, commonBeatMonitoringConfigGetter, logptest.NewTestingLogger(t, ""))

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

func TestOTelManager_handleOtelStatusUpdate(t *testing.T) {
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
			mgr := &OTelManager{
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

func TestOTelManager_processComponentStates(t *testing.T) {
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
			mgr := &OTelManager{
				logger:                 newTestLogger(),
				currentComponentStates: tt.currentComponentStates,
			}

			result := mgr.processComponentStates(tt.inputComponentStates)

			assert.ElementsMatch(t, tt.expectedOutputStates, result)
			assert.Equal(t, tt.expectedCurrentStatesAfter, mgr.currentComponentStates)
		})
	}
}

// TestOTelManagerEndToEnd tests the full lifecycle of the OTelManager
// including configuration updates, status updates, and error handling.
func TestOTelManagerEndToEnd(t *testing.T) {
	// Setup test logger and dependencies
	testLogger, _ := loggertest.New("test")
	agentInfo := &info.AgentInfo{}
	beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter
	collectorStarted := make(chan struct{})

	execution := &mockExecution{
		collectorStarted: collectorStarted,
	}

	// Create manager with test dependencies
	mgr := OTelManager{
		logger:                     testLogger,
		baseLogger:                 testLogger,
		errCh:                      make(chan error, 1), // holds at most one error
		updateCh:                   make(chan configUpdate),
		collectorStatusCh:          make(chan *status.AggregateStatus, 1),
		componentStateCh:           make(chan []runtime.ComponentComponentState, 1),
		doneChan:                   make(chan struct{}),
		recoveryTimer:              newRestarterNoop(),
		execution:                  execution,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
	}

	// Start manager in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
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
	components := []component.Component{testComp}

	t.Run("collector config is passed down to the collector execution", func(t *testing.T) {
		mgr.Update(collectorCfg, nil)
		select {
		case <-collectorStarted:
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector config update")
		}
		assert.Equal(t, collectorCfg, execution.cfg)

	})

	t.Run("collector status is passed up to the component manager", func(t *testing.T) {
		otelStatus := &status.AggregateStatus{
			Event: componentstatus.NewEvent(componentstatus.StatusOK),
		}

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case execution.statusCh <- otelStatus:
		}

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		assert.Equal(t, otelStatus, collectorStatus)
	})

	t.Run("component config is passed down to the otel manager", func(t *testing.T) {
		mgr.Update(collectorCfg, components)
		select {
		case <-collectorStarted:
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector config update")
		}
		cfg := execution.cfg
		require.NotNil(t, cfg)
		receivers, err := cfg.Sub("receivers")
		require.NoError(t, err)
		require.NotNil(t, receivers)
		assert.True(t, receivers.IsSet("nop"))
		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		assert.Nil(t, err)
		assert.Nil(t, collectorStatus)
	})

	t.Run("empty collector config leaves the component config running", func(t *testing.T) {
		mgr.Update(nil, components)
		select {
		case <-collectorStarted:
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector config update")
		}
		cfg := execution.cfg
		require.NotNil(t, cfg)
		receivers, err := cfg.Sub("receivers")
		require.NoError(t, err)
		require.NotNil(t, receivers)
		assert.False(t, receivers.IsSet("nop"))
		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		assert.Nil(t, err)
		assert.Nil(t, collectorStatus)
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
		case execution.statusCh <- otelStatus:
		}

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		require.NotNil(t, collectorStatus)
		assert.Len(t, collectorStatus.ComponentStatusMap, 0)

		componentState, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(t, err)
		require.NotNil(t, componentState)
		require.Len(t, componentState, 1)
		assert.Equal(t, componentState[0].Component, testComp)
	})

	t.Run("collector error is passed up to the component manager", func(t *testing.T) {
		collectorErr := errors.New("collector error")

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case execution.errCh <- collectorErr:
		}

		// we should get a nil status and an error
		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case s := <-mgr.WatchCollector():
			assert.Nil(t, s)
		}
		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case err := <-mgr.Errors():
			assert.Equal(t, collectorErr, err)
		}
	})
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
>>>>>>> 779fafdcd ([beatreceivers] Integrate beatsauthextension (#9257))
