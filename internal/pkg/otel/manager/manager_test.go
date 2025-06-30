// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/version"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/pkg/core/logger"
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

type mockExecution struct {
	mtx    sync.Mutex
	exec   collectorExecution
	handle collectorHandle
}

func (m *mockExecution) startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	var err error
	m.handle, err = m.exec.startCollector(ctx, logger, cfg, errCh, statusCh)
	return m.handle, err
}

func (m *mockExecution) getProcessHandle() collectorHandle {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	return m.handle
}

// EventListener listens to the events from the OTelManager and stores the latest error and status.
type EventListener struct {
	mtx    sync.Mutex
	err    *EventTime[error]
	status *EventTime[*status.AggregateStatus]
}

// Listen starts listening to the error and status channels. It updates the latest error and status in the
// EventListener.
func (e *EventListener) Listen(ctx context.Context, errorCh <-chan error, statusCh <-chan *status.AggregateStatus) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-statusCh:
			e.mtx.Lock()
			e.status = &EventTime[*status.AggregateStatus]{val: c, time: time.Now()}
			e.mtx.Unlock()
		case c := <-errorCh:
			e.mtx.Lock()
			e.err = &EventTime[error]{val: c, time: time.Now()}
			e.mtx.Unlock()
		}
	}
}

// getError retrieves the latest error from the EventListener.
func (e *EventListener) getError() error {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return e.err.Value()
}

// getStatus retrieves the latest status from the EventListener.
func (e *EventListener) getStatus() *status.AggregateStatus {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return e.status.Value()
}

// EnsureHealthy ensures that the OTelManager is healthy by checking the latest error and status.
func (e *EventListener) EnsureHealthy(t *testing.T, u time.Time) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.status
		e.mtx.Unlock()

		// we expect to have a reported error which is nil and a reported status which is StatusOK
		require.NotNil(collect, latestErr)
		assert.Nil(collect, latestErr.Value())
		assert.False(collect, latestErr.Before(u))
		require.NotNil(collect, latestStatus)
		require.NotNil(collect, latestStatus.Value())
		assert.False(collect, latestStatus.Before(u))
		require.Equal(collect, componentstatus.StatusOK, latestStatus.Value().Status())
	}, 60*time.Second, 1*time.Second, "otel collector never got healthy")
}

// EnsureOffWithoutError ensures that the OTelManager is off without an error by checking the latest error and status.
func (e *EventListener) EnsureOffWithoutError(t *testing.T, u time.Time) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.status
		e.mtx.Unlock()

		// we expect to have a reported error which is nil and a reported status which is nil
		require.NotNil(collect, latestErr)
		assert.Nil(collect, latestErr.Value())
		assert.False(collect, latestErr.Before(u))
		require.NotNil(collect, latestStatus)
		assert.Nil(collect, latestStatus.Value())
		assert.False(collect, latestStatus.Before(u))
	}, 60*time.Second, 1*time.Second, "otel collector never stopped without an error")
}

// EnsureOffWithError ensures that the OTelManager is off with an error by checking the latest error and status.
func (e *EventListener) EnsureOffWithError(t *testing.T, u time.Time) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.status
		e.mtx.Unlock()

		// we expect to have a reported error which is not nil and a reported status which is nil
		require.False(collect, latestErr == nil || latestErr.Before(u) || latestErr.Value() == nil)
		require.False(collect, latestStatus == nil || latestStatus.Before(u) || latestStatus.Value() != nil)
	}, 60*time.Second, 1*time.Second, "otel collector never errored with an error")
}

// EventTime is a wrapper around a time.Time and a value of type T. It provides methods to compare the time and retrieve the value.
type EventTime[T interface{}] struct {
	time time.Time
	val  T
}

// Before checks if the EventTime's time is before the given time u.
func (t *EventTime[T]) Before(u time.Time) bool {
	return t != nil && t.time.Before(u)
}

// Value retrieves the value of type T from the EventTime. If the EventTime is nil, it returns the zero value of T.
func (t *EventTime[T]) Value() T {
	if t == nil {
		var zero T
		return zero
	}
	return t.val
}

// Time retrieves the time associated with the EventTime. If the EventTime is nil, it returns the zero value of time.Time.
func (t *EventTime[T]) Time() time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.time
}

func TestOTelManager_Run(t *testing.T) {
	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	for _, tc := range []struct {
		name                string
		exec                *mockExecution
		restarter           collectorRecoveryTimer
		skipListeningErrors bool
		testFn              func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution)
	}{
		{
			name:      "embedded collector config updates",
			exec:      &mockExecution{exec: newExecutionEmbedded()},
			restarter: newRestarterNoop(),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// trigger update (no config compare is due externally to otel collector)
				updateTime = time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				require.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
			},
		},
		{
			name:      "subprocess collector config updates",
			exec:      &mockExecution{exec: newSubprocessExecution(logp.DebugLevel, testBinary)},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// trigger update (no config compare is due externally to otel collector)
				updateTime = time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(0), m.recoveryRetries.Load(), "recovery retries should be 0")
			},
		},
		{
			name:      "embedded collector stopped gracefully outside manager",
			exec:      &mockExecution{exec: newExecutionEmbedded()},
			restarter: newRestarterNoop(),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				require.NotNil(t, exec.handle, "exec handle should not be nil")
				exec.handle.Stop(t.Context())
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				require.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
			},
		},
		{
			name:      "subprocess collector stopped gracefully outside manager",
			exec:      &mockExecution{exec: newSubprocessExecution(logp.DebugLevel, testBinary)},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				require.NotNil(t, exec.handle, "exec handle should not be nil")
				exec.handle.Stop(t.Context())
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(0), m.recoveryRetries.Load(), "recovery retries should be 0")
			},
		},
		{
			name:      "subprocess collector killed outside manager",
			exec:      &mockExecution{exec: newSubprocessExecution(logp.DebugLevel, testBinary)},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.UpdateCollector(cfg)
				e.EnsureHealthy(t, updateTime)

				var oldPHandle *procHandle
				// repeatedly kill the collector
				for i := 0; i < 3; i++ {
					// kill it
					handle := exec.getProcessHandle()
					require.NotNil(t, handle, "exec handle should not be nil, iteration ", i)
					pHandle, ok := handle.(*procHandle)
					require.True(t, ok, "exec handle should be of type procHandle, iteration ", i)
					if oldPHandle != nil {
						require.NotEqual(t, pHandle.processInfo.PID, oldPHandle.processInfo.PID, "processes PIDs should be different, iteration ", i)
					}
					oldPHandle = pHandle
					require.NoError(t, pHandle.processInfo.Kill(), "failed to kill collector process, iteration ", i)
					// the collector should restart and report healthy
					updateTime = time.Now()
					e.EnsureHealthy(t, updateTime)
				}

				seenRecoveredTimes := m.recoveryRetries.Load()

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(3), seenRecoveredTimes, "recovery retries should be 3")
			},
		},
		{
			name:      "subprocess collector panics",
			exec:      &mockExecution{exec: newSubprocessExecution(logp.DebugLevel, testBinary)},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				err := os.Setenv("TEST_SUPERVISED_COLLECTOR_PANIC", (3 * time.Second).String())
				require.NoError(t, err, "failed to set TEST_SUPERVISED_COLLECTOR_PANIC env var")
				t.Cleanup(func() {
					_ = os.Unsetenv("TEST_SUPERVISED_COLLECTOR_PANIC")
				})

				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				m.UpdateCollector(cfg)

				seenRecoveredTimes := uint32(0)
				require.Eventually(t, func() bool {
					seenRecoveredTimes = m.recoveryRetries.Load()
					return seenRecoveredTimes > 2
				}, time.Minute, time.Second, "expected recovered times to be at least 3, got %d", seenRecoveredTimes)

				err = os.Unsetenv("TEST_SUPERVISED_COLLECTOR_PANIC")
				require.NoError(t, err, "failed to unset TEST_SUPERVISED_COLLECTOR_PANIC env var")
				updateTime := time.Now()
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.UpdateCollector(nil)
				e.EnsureOffWithoutError(t, updateTime)
				require.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.GreaterOrEqual(t, uint32(3), seenRecoveredTimes, "recovery retries should be 3")
			},
		},
		{
			name:                "embedded collector invalid config",
			exec:                &mockExecution{exec: newExecutionEmbedded()},
			restarter:           newRestarterNoop(),
			skipListeningErrors: true,
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// Errors channel is non-blocking, should be able to send an Update that causes an error multiple
				// times without it blocking on sending over the errCh.
				for range 3 {
					cfg := confmap.New() // invalid config
					m.UpdateCollector(cfg)

					// delay between updates to ensure the collector will have to fail
					<-time.After(100 * time.Millisecond)
				}

				// because of the retry logic and timing we need to ensure
				// that this keeps retrying to see the error and only store
				// an actual error
				//
				// a nil error just means that the collector is trying to restart
				// which clears the error on the restart loop
				timeoutCh := time.After(time.Minute * 5)
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
			},
		},
		{
			name:                "subprocess collector invalid config",
			exec:                &mockExecution{exec: newSubprocessExecution(logp.DebugLevel, testBinary)},
			restarter:           newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			skipListeningErrors: true,
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *mockExecution) {
				// Errors channel is non-blocking, should be able to send an Update that causes an error multiple
				// times without it blocking on sending over the errCh.
				for range 3 {
					cfg := confmap.New() // invalid config
					m.UpdateCollector(cfg)

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
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l, _ := loggertest.New("otel")
			base, obs := loggertest.New("otel")
			m := &OTelManager{
				logger:            l,
				baseLogger:        base,
				errCh:             make(chan error, 1), // holds at most one error
				collectorUpdateCh: make(chan *confmap.Conf),
				collectorStatusCh: make(chan *status.AggregateStatus),
				doneChan:          make(chan struct{}),
				recoveryTimer:     tc.restarter,
				execution:         tc.exec,
			}

			eListener := &EventListener{}
			defer func() {
				if !t.Failed() {
					return
				}
				t.Logf("latest received err: %s", eListener.getError())
				t.Logf("latest received status: %s", statusToYaml(eListener.getStatus()))
				for _, entry := range obs.All() {
					t.Logf("%+v", entry)
				}
			}()

			runWg := sync.WaitGroup{}
			runWg.Add(1)
			go func() {
				defer runWg.Done()
				if !tc.skipListeningErrors {
					eListener.Listen(ctx, m.Errors(), m.WatchCollector())
				} else {
					eListener.Listen(ctx, nil, m.WatchCollector())
				}
			}()

			var runErr error
			runWg.Add(1)
			go func() {
				defer runWg.Done()
				runErr = m.Run(ctx)
			}()

			tc.testFn(t, m, eListener, tc.exec)

			cancel()
			runWg.Wait()
			if !errors.Is(runErr, context.Canceled) {
				t.Errorf("otel manager returned unexpected error: %v", runErr)
			}
		})
	}
}

func TestOTelManager_Logging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, obs := loggertest.New("otel")
	l, _ := loggertest.New("otel-manager")
	m, err := NewOTelManager(l, logp.DebugLevel, base, EmbeddedExecutionMode, nil, nil)
	require.NoError(t, err, "could not create otel manager")

	go func() {
		err := m.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled, "otel manager should be cancelled")
	}()

	// watch is synchronous, so we need to read from it to avoid blocking the manager
	go func() {
		for {
			select {
			case <-m.WatchCollector():
			case <-ctx.Done():
				return
			}
		}
	}()

	cfg := confmap.NewFromStringMap(testConfig)
	m.UpdateCollector(cfg)

	// the collector should log to the base logger
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		logs := obs.All()
		require.NotEmpty(collect, logs, "Logs should not be empty")
		firstMessage := logs[0].Message
		assert.Equal(collect, firstMessage, "Setting up own telemetry...")
	}, time.Second*10, time.Second)
}

// statusToYaml converts the status.AggregateStatus to a YAML string representation.
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
			mgr := &OTelManager{
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

func TestOTelManager_handleComponentUpdate(t *testing.T) {
	testComp := testComponent("test-component")
	t.Run("successful update with empty model", func(t *testing.T) {
		mgr := &OTelManager{
			logger:                     newTestLogger(),
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		model := component.Model{Components: nil}
		err := mgr.handleComponentUpdate(model)

		assert.NoError(t, err)
		assert.Equal(t, model.Components, mgr.components)
		// Verify that Update was called with nil config (empty components should result in nil config)
		assert.Nil(t, mgr.mergedCollectorCfg)
	})

	t.Run("successful update with components", func(t *testing.T) {
		mgr := &OTelManager{
			logger:                     newTestLogger(),
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		// Use a valid component that will generate otel config
		model := component.Model{Components: []component.Component{testComp}}

		err := mgr.handleComponentUpdate(model)

		assert.NoError(t, err)
		assert.Equal(t, model.Components, mgr.components)
		// Verify that Update was called with a valid configuration
		assert.NotNil(t, mgr.mergedCollectorCfg)
		// Verify that the configuration contains expected OpenTelemetry sections
		assert.True(t, mgr.mergedCollectorCfg.IsSet("receivers"), "Expected receivers section in config")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("exporters"), "Expected exporters section in config")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("service"), "Expected service section in config")
	})
}

func TestOTelManager_handleCollectorUpdate(t *testing.T) {
	t.Run("successful update with nil collector config", func(t *testing.T) {
		mgr := &OTelManager{
			logger:                     newTestLogger(),
			agentInfo:                  &info.AgentInfo{},
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
		}

		err := mgr.handleCollectorUpdate(nil)

		assert.NoError(t, err)
		assert.Nil(t, mgr.collectorCfg)
		assert.Nil(t, mgr.MergedOtelConfig())
		// Verify that Update was called with nil config (no collector config should result in nil config)
		assert.Nil(t, mgr.mergedCollectorCfg)
	})

	t.Run("successful update with collector config", func(t *testing.T) {
		mgr := &OTelManager{
			logger:                     newTestLogger(),
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
		assert.NotNil(t, mgr.mergedCollectorCfg)
		// Verify that the configuration contains expected collector sections
		assert.True(t, mgr.mergedCollectorCfg.IsSet("receivers"), "Expected receivers section in config")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("processors"), "Expected processors section in config")
	})

	t.Run("successful update with both collector config and existing components", func(t *testing.T) {
		mgr := &OTelManager{
			logger:                     newTestLogger(),
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
		// Verify that the configuration contains both collector and component sections
		assert.True(t, mgr.mergedCollectorCfg.IsSet("receivers"), "Expected receivers section from components")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("exporters"), "Expected exporters section from components")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("service"), "Expected service section from components")
		assert.True(t, mgr.mergedCollectorCfg.IsSet("processors"), "Expected processors section from collector config")
	})
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
//func TestOTelManagerEndToEnd(t *testing.T) {
//	// Setup test logger and dependencies
//	testLogger, _ := loggertest.New("test")
//	agentInfo := &info.AgentInfo{}
//	beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter
//
//	otelStatusChan := make(chan *status.AggregateStatus, 1)
//	otelErrChan := make(chan error, 1)
//	otelConfigChan := make(chan *confmap.Conf, 1)
//	otelManager := &fakeOTelManager{
//		updateCallback: func(cfg *confmap.Conf) error {
//			otelConfigChan <- cfg
//			return nil
//		},
//		statusChan: otelStatusChan,
//		errChan:    otelErrChan,
//	}
//
//	// Create manager with test dependencies
//	mgr := OTelManager{
//		logger:                 testLogger,
//		otelManager:            otelManager,
//		agentInfo:              agentInfo,
//		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
//		collectorStatusCh:      otelStatusChan,
//		errCh:                  otelErrChan,
//		collectorUpdateCh:      otelConfigChan,
//	}
//	require.NotNil(t, mgr)
//
//	// Start manager in a goroutine
//	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*1)
//	defer cancel()
//
//	go func() {
//		err := mgr.Run(ctx)
//		assert.ErrorIs(t, err, context.Canceled)
//	}()
//
//	collectorCfg := confmap.NewFromStringMap(map[string]interface{}{
//		"receivers": map[string]interface{}{
//			"nop": map[string]interface{}{},
//		},
//		"exporters": map[string]interface{}{"nop": map[string]interface{}{}},
//		"service": map[string]interface{}{
//			"pipelines": map[string]interface{}{
//				"metrics": map[string]interface{}{
//					"receivers": []string{"nop"},
//					"exporters": []string{"nop"},
//				},
//			},
//		},
//	})
//
//	testComp := testComponent("test")
//
//	componentModel := component.Model{
//		Components: []component.Component{
//			testComp,
//		},
//	}
//
//	t.Run("collector config is passed down to the otel manager", func(t *testing.T) {
//		mgr.UpdateCollector(collectorCfg)
//		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
//		require.NoError(t, err)
//		assert.Equal(t, collectorCfg, cfg)
//	})
//
//	t.Run("collector status is passed up to the component manager", func(t *testing.T) {
//		otelStatus := &status.AggregateStatus{
//			Event: componentstatus.NewEvent(componentstatus.StatusOK),
//		}
//
//		select {
//		case <-ctx.Done():
//			t.Fatal("timeout waiting for collector status update")
//		case otelStatusChan <- otelStatus:
//		}
//
//		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
//		require.NoError(t, err)
//		assert.Equal(t, otelStatus, collectorStatus)
//	})
//
//	t.Run("component config is passed down to the otel manager", func(t *testing.T) {
//		mgr.UpdateComponents(componentModel)
//		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
//		require.NoError(t, err)
//		require.NotNil(t, cfg)
//		receivers, err := cfg.Sub("receivers")
//		require.NoError(t, err)
//		require.NotNil(t, receivers)
//		assert.True(t, receivers.IsSet("nop"))
//		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))
//	})
//
//	t.Run("empty collector config leaves the component config running", func(t *testing.T) {
//		mgr.UpdateCollector(nil)
//		cfg, err := getFromChannelOrErrorWithContext(t, ctx, otelConfigChan, mgr.Errors())
//		require.NotNil(t, cfg)
//		require.NoError(t, err)
//		receivers, err := cfg.Sub("receivers")
//		require.NoError(t, err)
//		require.NotNil(t, receivers)
//		assert.False(t, receivers.IsSet("nop"))
//		assert.True(t, receivers.IsSet("filebeatreceiver/_agent-component/test"))
//	})
//
//	t.Run("collector status with components is passed up to the component manager", func(t *testing.T) {
//		otelStatus := &status.AggregateStatus{
//			Event: componentstatus.NewEvent(componentstatus.StatusOK),
//			ComponentStatusMap: map[string]*status.AggregateStatus{
//				// This represents a pipeline for our component (with OtelNamePrefix)
//				"pipeline:logs/_agent-component/test": {
//					Event: componentstatus.NewEvent(componentstatus.StatusOK),
//					ComponentStatusMap: map[string]*status.AggregateStatus{
//						"receiver:filebeatreceiver/_agent-component/test": {
//							Event: componentstatus.NewEvent(componentstatus.StatusOK),
//						},
//						"exporter:elasticsearch/_agent-component/test": {
//							Event: componentstatus.NewEvent(componentstatus.StatusOK),
//						},
//					},
//				},
//			},
//		}
//
//		select {
//		case <-ctx.Done():
//			t.Fatal("timeout waiting for collector status update")
//		case otelStatusChan <- otelStatus:
//		}
//
//		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
//		require.NoError(t, err)
//		assert.Len(t, collectorStatus.ComponentStatusMap, 0)
//
//		componentState, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
//		require.NoError(t, err)
//		assert.Equal(t, componentState.Component, testComp)
//	})
//
//	t.Run("collector error is passed up to the component manager", func(t *testing.T) {
//		collectorErr := errors.New("collector error")
//
//		select {
//		case <-ctx.Done():
//			t.Fatal("timeout waiting for collector status update")
//		case otelErrChan <- collectorErr:
//		}
//
//		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
//		require.Nil(t, collectorStatus)
//		assert.Equal(t, err, collectorErr)
//	})
//}

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
