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
		require.False(collect, latestErr == nil || latestErr.Before(u) || latestErr.Value() != nil)
		require.False(collect, latestStatus == nil || latestStatus.Value() == nil || latestStatus.Before(u) || latestStatus.Value().Status() != componentstatus.StatusOK)
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
		require.False(collect, latestErr == nil || latestErr.Before(u) || latestErr.Value() != nil)
		require.False(collect, latestStatus == nil || latestStatus.Before(u) || latestStatus.Value() != nil)
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
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// trigger update (no config compare is due externally to otel collector)
				updateTime = time.Now()
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil)
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
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// trigger update (no config compare is due externally to otel collector)
				updateTime = time.Now()
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil)
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
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				require.NotNil(t, exec.handle, "exec handle should not be nil")
				exec.handle.Stop(t.Context())
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil)
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
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				require.NotNil(t, exec.handle, "exec handle should not be nil")
				exec.handle.Stop(t.Context())
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil)
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
				m.Update(cfg)
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
				m.Update(nil)
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
				m.Update(cfg)

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
				m.Update(nil)
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
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			l, _ := loggertest.New("otel")
			base, _ := loggertest.New("otel")
			m := &OTelManager{
				logger:        l,
				baseLogger:    base,
				errCh:         make(chan error, 1), // holds at most one error
				cfgCh:         make(chan *confmap.Conf),
				statusCh:      make(chan *status.AggregateStatus),
				doneChan:      make(chan struct{}),
				recoveryTimer: tc.restarter,
				execution:     tc.exec,
			}

			eListener := &EventListener{}
			defer func() {
				if !t.Failed() {
					return
				}
				t.Logf("latest received err: %s", eListener.getError())
				t.Logf("latest received status: %s", statusToYaml(eListener.getStatus()))
			}()

			runWg := sync.WaitGroup{}
			runWg.Add(1)
			go func() {
				defer runWg.Done()
				if !tc.skipListeningErrors {
					eListener.Listen(ctx, m.Errors(), m.Watch())
				} else {
					eListener.Listen(ctx, nil, m.Watch())
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
