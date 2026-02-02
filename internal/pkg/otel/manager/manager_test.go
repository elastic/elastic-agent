// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otelComponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/component/runtime"
	"github.com/elastic/elastic-agent/version"

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
				"logs": map[string]interface{}{
					"level": "info",
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

	testConfigNoLogLevel = map[string]interface{}{
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
				"logs": map[string]interface{}{
					"receivers":  []string{"nop"},
					"processors": []string{"batch"},
					"exporters":  []string{"nop"},
				},
			},
		},
	}
)

type testExecution struct {
	mtx    sync.Mutex
	exec   collectorExecution
	handle collectorHandle
}

func (e *testExecution) startCollector(ctx context.Context, level logp.Level, collectorLogger *logger.Logger, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus, forceFetchStatusCh chan struct{}) (collectorHandle, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var err error
	e.handle, err = e.exec.startCollector(ctx, level, collectorLogger, logger, cfg, errCh, statusCh, forceFetchStatusCh)
	return e.handle, err
}

func (e *testExecution) getProcessHandle() collectorHandle {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	return e.handle
}

var _ collectorExecution = &mockExecution{}

type mockExecution struct {
	errCh            chan error
	statusCh         chan *status.AggregateStatus
	cfg              *confmap.Conf
	collectorStarted chan struct{}
}

func (e *mockExecution) startCollector(
	ctx context.Context,
	level logp.Level,
	_ *logger.Logger,
	_ *logger.Logger,
	cfg *confmap.Conf,
	errCh chan error,
	statusCh chan *status.AggregateStatus,
	_ chan struct{},
) (collectorHandle, error) {
	e.errCh = errCh
	e.statusCh = statusCh
	e.cfg = cfg
	stopCh := make(chan struct{})
	collectorCtx, collectorCancel := context.WithCancel(ctx)
	go func() {
		<-collectorCtx.Done()
		close(stopCh)
		reportErr(ctx, errCh, nil)
	}()
	handle := &mockCollectorHandle{
		stopCh: stopCh,
		cancel: collectorCancel,
	}
	if e.collectorStarted != nil {
		e.collectorStarted <- struct{}{}
	}
	return handle, nil
}

var _ collectorHandle = &mockCollectorHandle{}

type mockCollectorHandle struct {
	stopCh chan struct{}
	cancel context.CancelFunc
}

func (h *mockCollectorHandle) Stop(waitTime time.Duration) {
	h.cancel()
	select {
	case <-time.After(waitTime):
	case <-h.stopCh:
	}
}

// EventListener listens to the events from the OTelManager and stores the latest error and status.
type EventListener struct {
	mtx             sync.Mutex
	err             *EventTime[error]
	collectorStatus *EventTime[*status.AggregateStatus]
	componentStates *EventTime[[]runtime.ComponentComponentState]
}

// Listen starts listening to the error and status channels. It updates the latest error and status in the
// EventListener.
func (e *EventListener) Listen(
	ctx context.Context,
	errorCh <-chan error,
	collectorStatusCh <-chan *status.AggregateStatus,
	componentStateCh <-chan []runtime.ComponentComponentState,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-collectorStatusCh:
			e.mtx.Lock()
			e.collectorStatus = &EventTime[*status.AggregateStatus]{val: c, time: time.Now()}
			e.mtx.Unlock()
		case c := <-errorCh:
			e.mtx.Lock()
			e.err = &EventTime[error]{val: c, time: time.Now()}
			e.mtx.Unlock()
		case componentStates := <-componentStateCh:
			e.mtx.Lock()
			e.componentStates = &EventTime[[]runtime.ComponentComponentState]{val: componentStates, time: time.Now()}
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

// getCollectorStatus retrieves the latest collector status from the EventListener.
func (e *EventListener) getCollectorStatus() *status.AggregateStatus {
	e.mtx.Lock()
	defer e.mtx.Unlock()
	return e.collectorStatus.Value()
}

// EnsureHealthy ensures that the OTelManager is healthy by checking the latest error and status.
func (e *EventListener) EnsureHealthy(t *testing.T, u time.Time) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.collectorStatus
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

// EnsureFatal ensures that the OTelManager is fatal by checking the latest error and status.
func (e *EventListener) EnsureFatal(t *testing.T, u time.Time, extraT ...func(collectT *assert.CollectT, latestErr *EventTime[error], latestStatus *EventTime[*status.AggregateStatus])) {
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.collectorStatus
		e.mtx.Unlock()

		// we expect to have a reported error which is nil and a reported status which is StatusOK
		require.NotNil(collect, latestErr)
		assert.Nil(collect, latestErr.Value())
		assert.False(collect, latestErr.Before(u))
		require.NotNil(collect, latestStatus)
		require.NotNil(collect, latestStatus.Value())
		assert.False(collect, latestStatus.Before(u))
		require.Equal(collect, componentstatus.StatusFatalError, latestStatus.Value().Status())

		// extra checks
		for _, et := range extraT {
			et(collect, latestErr, latestStatus)
		}
	}, 60*time.Second, 1*time.Second, "otel collector never fatal")
}

// EnsureOffWithoutError ensures that the OTelManager is off without an error by checking the latest error and status.
func (e *EventListener) EnsureOffWithoutError(t *testing.T, u time.Time) {
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		e.mtx.Lock()
		latestErr := e.err
		latestStatus := e.collectorStatus
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
		latestStatus := e.collectorStatus
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

func countHealthCheckExtensionStatuses(status *status.AggregateStatus) uint {
	if status == nil {
		return 0
	}
	extensions, ok := status.ComponentStatusMap["extensions"]
	if !ok {
		return 0
	}

	count := uint(0)
	for key := range extensions.ComponentStatusMap {
		if strings.HasPrefix(key, "extension:healthcheckv2/") {
			count++
		}
	}

	return count
}

func TestOTelManager_Run(t *testing.T) {
	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "..", "..", "..", "..", "internal", "edot", "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	const waitTimeForStop = 30 * time.Second

	for _, tc := range []struct {
		name                string
		execModeFn          func(collectorRunErr chan error) (collectorExecution, error)
		restarter           collectorRecoveryTimer
		skipListeningErrors bool
		testFn              func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error)
	}{
		{
			name: "subprocess collector config updates",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				// trigger update
				updateTime = time.Now()
				ok := cfg.Delete("service::telemetry::logs::level") // modify the config
				require.True(t, ok)
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil, nil, logp.InfoLevel, nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(0), m.recoveryRetries.Load(), "recovery retries should be 0")
			},
		},
		{
			name: "subprocess collector stopped gracefully outside manager",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				execHandle := exec.getProcessHandle()
				require.NotNil(t, execHandle, "execModeFn handle should not be nil")
				execHandle.Stop(waitTimeForStop)
				e.EnsureHealthy(t, updateTime)
				require.EqualValues(t, 0, countHealthCheckExtensionStatuses(e.getCollectorStatus()), "health check extension status count should be 0")

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil, nil, logp.InfoLevel, nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(0), m.recoveryRetries.Load(), "recovery retries should be 0")
			},
		},
		{
			name: "subprocess collector killed outside manager",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)
				require.EqualValues(t, 0, countHealthCheckExtensionStatuses(e.getCollectorStatus()), "health check extension status count should be 0")

				var oldPHandle *procHandle
				// repeatedly kill the collector
				for i := 0; i < 3; i++ {
					// kill it
					handle := exec.getProcessHandle()
					require.NotNil(t, handle, "execModeFn handle should not be nil, iteration ", i)
					pHandle, ok := handle.(*procHandle)
					require.True(t, ok, "execModeFn handle should be of type procHandle, iteration ", i)
					if oldPHandle != nil {
						require.NotEqual(t, pHandle.processInfo.PID, oldPHandle.processInfo.PID, "processes PIDs should be different, iteration ", i)
					}
					oldPHandle = pHandle
					require.NoError(t, pHandle.processInfo.Kill(), "failed to kill collector process, iteration ", i)
					// the collector should restart and report healthy
					updateTime = time.Now()
					e.EnsureHealthy(t, updateTime)
					require.EqualValues(t, 0, countHealthCheckExtensionStatuses(e.getCollectorStatus()), "health check extension status count should be 0")
				}

				seenRecoveredTimes := m.recoveryRetries.Load()

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil, nil, logp.InfoLevel, nil)
				e.EnsureOffWithoutError(t, updateTime)
				assert.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.Equal(t, uint32(3), seenRecoveredTimes, "recovery retries should be 3")
			},
		},
		{
			name: "subprocess collector panics restarts",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				err := os.Setenv("TEST_SUPERVISED_COLLECTOR_PANIC", (3 * time.Second).String())
				require.NoError(t, err, "failed to set TEST_SUPERVISED_COLLECTOR_PANIC env var")
				t.Cleanup(func() {
					_ = os.Unsetenv("TEST_SUPERVISED_COLLECTOR_PANIC")
				})

				cfg := confmap.NewFromStringMap(testConfig)
				m.Update(cfg, nil, logp.InfoLevel, nil)

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
				m.Update(nil, nil, logp.InfoLevel, nil)
				e.EnsureOffWithoutError(t, updateTime)
				require.True(t, m.recoveryTimer.IsStopped(), "restart timer should be stopped")
				assert.GreaterOrEqual(t, uint32(3), seenRecoveredTimes, "recovery retries should be 3")
			},
		},
		{
			name: "subprocess collector panics reports fatal",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// panic instantly always
				err := os.Setenv("TEST_SUPERVISED_COLLECTOR_PANIC", "0s")
				require.NoError(t, err, "failed to set TEST_SUPERVISED_COLLECTOR_PANIC env var")
				t.Cleanup(func() {
					_ = os.Unsetenv("TEST_SUPERVISED_COLLECTOR_PANIC")
				})

				cfg := confmap.NewFromStringMap(testConfig)
				m.Update(cfg, nil, logp.InfoLevel, nil)

				// ensure that it reports a generic fatal error for all components, a panic cannot be assigned to
				// a specific component in the collector
				e.EnsureFatal(t, time.Now().Add(time.Second), func(collectT *assert.CollectT, _ *EventTime[error], latestStatus *EventTime[*status.AggregateStatus]) {
					status := latestStatus.Value()

					// healthcheck auto added
					extensions, ok := status.ComponentStatusMap["extensions"]
					require.True(collectT, ok, "extensions should be present")
					assert.Equal(collectT, extensions.Status(), componentstatus.StatusFatalError)

					metrics, ok := status.ComponentStatusMap["pipeline:metrics"]
					require.True(collectT, ok, "pipeline metrics should be present")
					assert.Equal(collectT, metrics.Status(), componentstatus.StatusFatalError)

					logs, ok := status.ComponentStatusMap["pipeline:logs"]
					require.True(collectT, ok, "pipeline logs should be present")
					assert.Equal(collectT, logs.Status(), componentstatus.StatusFatalError)

					traces, ok := status.ComponentStatusMap["pipeline:traces"]
					require.True(collectT, ok, "pipeline traces should be present")
					assert.Equal(collectT, traces.Status(), componentstatus.StatusFatalError)
				})
			},
		},
		{
			name: "subprocess collector killed if delayed and manager is stopped",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				subprocessExec, err := newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
				if err != nil {
					return nil, err
				}
				subprocessExec.reportErrFn = func(ctx context.Context, errCh chan error, err error) {
					// override the reportErrFn to send the error to this test collectorRunErr channel
					// so we can listen to subprocess run errors
					if errCh != collectorRunErr {
						// if the error channel is not the one we expect, forward the error to the original reportErrFn
						reportErr(ctx, errCh, err)
						return
					}
					collectorRunErr <- err
				}
				return &testExecution{exec: subprocessExec}, nil
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				delayDuration := 40 * time.Second // the otel manager stop timeout is waitTimeForStop (30 seconds)
				t.Setenv("TEST_SUPERVISED_COLLECTOR_DELAY", delayDuration.String())

				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				// stop the manager to simulate that elastic-agent is shutting down
				managerCtxCancel()

				// wait for the manager to report done
				select {
				case <-m.doneChan:
				case <-time.After(10 * time.Second):
					require.Fail(t, "manager should have reported done")
				case <-t.Context().Done():
					return
				}

				// wait for the subprocess to exit by checking the collectorRunErr channel
				select {
				case err := <-collectorRunErr:
					require.Error(t, err, "process should have exited with an error")
				case <-t.Context().Done():
					return
				case <-time.After(2 * waitTimeForStop):
					require.Fail(t, "timeout waiting for process to exit")
				}
			},
		},
		{
			name: "subprocess collector gracefully exited if delayed a bit and manager is stopped",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				subprocessExec, err := newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
				if err != nil {
					return nil, err
				}
				subprocessExec.reportErrFn = func(ctx context.Context, errCh chan error, err error) {
					// override the reportErrFn to send the error to this test collectorRunErr channel
					// so we can listen to subprocess run errors
					if errCh != collectorRunErr {
						// if the error channel is not the one we expect, forward the error to the original reportErrFn
						reportErr(ctx, errCh, err)
						return
					}
					collectorRunErr <- err
				}
				return &testExecution{exec: subprocessExec}, nil
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				delayDuration := 5 * time.Second // the otel manager stop timeout is waitTimeForStop (30 seconds)
				t.Setenv("TEST_SUPERVISED_COLLECTOR_DELAY", delayDuration.String())

				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				// stop the manager to simulate that elastic-agent is shutting down
				managerCtxCancel()

				// wait for the manager to report done
				select {
				case <-m.doneChan:
				case <-time.After(10 * time.Second):
					require.Fail(t, "manager should have reported done")
				case <-t.Context().Done():
					return
				}

				// wait for the subprocess to exit by checking the collectorRunErr channel
				select {
				case err := <-collectorRunErr:
					require.NoError(t, err, "process should have exited without an error")
				case <-t.Context().Done():
					return
				case <-time.After(2 * waitTimeForStop):
					require.Fail(t, "timeout waiting for process to exit")
				}
			},
		},
		{
			name: "subprocess user has healthcheck extension",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {

				subprocessExec, ok := exec.exec.(*subprocessExecution)
				require.True(t, ok, "execution mode isn't subprocess")

				cfg := confmap.NewFromStringMap(testConfig)

				nsUUID, err := uuid.NewV4()
				require.NoError(t, err, "failed to create a uuid")

				componentType, err := otelComponent.NewType(healthCheckExtensionName)
				require.NoError(t, err, "failed to create component type")

				healthCheckExtensionID := otelComponent.NewIDWithName(componentType, nsUUID.String()).String()

				ports, err := findRandomTCPPorts(3)
				require.NoError(t, err, "failed to find random tcp ports")
				subprocessExec.collectorHealthCheckPort = ports[0]
				subprocessExec.collectorMetricsPort = ports[1]
				err = injectHealthCheckV2Extension(cfg, healthCheckExtensionID, ports[2])
				require.NoError(t, err, "failed to inject user health extension")

				updateTime := time.Now()
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureHealthy(t, updateTime)

				require.EqualValues(t, 1, countHealthCheckExtensionStatuses(e.getCollectorStatus()), "health check extension status count should be 1")
			},
		},
		{
			name: "subprocess collector empty config",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter:           newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			skipListeningErrors: true,
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// Errors channel is non-blocking, should be able to send an Update that causes an error multiple
				// times without it blocking on sending over the errCh.
				for range 3 {
					// empty config
					//
					// this is really validating a flow that is not possible with the elastic-agent
					// if the OTEL configuration is determined to be empty then it will not be ran
					//
					// this does give a good test of a truly invalid configuration
					cfg := confmap.New() // empty config
					m.Update(cfg, nil, logp.InfoLevel, nil)

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
			name: "subprocess collector failed to start",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
			restarter: newRecoveryBackoff(100*time.Nanosecond, 10*time.Second, time.Minute),
			testFn: func(t *testing.T, m *OTelManager, e *EventListener, exec *testExecution, managerCtxCancel context.CancelFunc, collectorRunErr chan error) {
				// not valid receivers/exporters
				//
				// this needs to be reported as status errors
				cfg := confmap.NewFromStringMap(map[string]interface{}{
					"receivers": map[string]interface{}{
						"invalid_receiver": map[string]interface{}{},
					},
					"exporters": map[string]interface{}{
						"invalid_exporter": map[string]interface{}{},
					},
					"service": map[string]interface{}{
						"pipelines": map[string]interface{}{
							"traces": map[string]interface{}{
								"receivers": []string{"invalid_receiver"},
								"exporters": []string{"invalid_exporter"},
							},
						},
					},
				})
				m.Update(cfg, nil, logp.InfoLevel, nil)
				e.EnsureFatal(t, time.Now().Add(time.Second), func(collectT *assert.CollectT, _ *EventTime[error], latestStatus *EventTime[*status.AggregateStatus]) {
					status := latestStatus.Value()

					// healthcheck auto added
					_, ok := status.ComponentStatusMap["extensions"]
					require.True(collectT, ok, "extensions should be present")

					traces, ok := status.ComponentStatusMap["pipeline:traces"]
					require.True(collectT, ok, "pipeline traces should be present")
					assert.Equal(collectT, traces.Status(), componentstatus.StatusFatalError)

					exporter, ok := traces.ComponentStatusMap["exporter:invalid_exporter"]
					require.True(collectT, ok, "exporter should be present")
					receiver, ok := traces.ComponentStatusMap["receiver:invalid_receiver"]
					require.True(collectT, ok, "receiver should be present")

					// both invalid_receiver and invalid_exporter are invalid
					assert.Equal(collectT, exporter.Status(), componentstatus.StatusFatalError)
					assert.Equal(collectT, receiver.Status(), componentstatus.StatusFatalError)
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l, _ := loggertest.New("otel")
			base, obs := loggertest.New("otel")

			m := &OTelManager{
				managerLogger:     l,
				collectorLogger:   base,
				errCh:             make(chan error, 1), // holds at most one error
				updateCh:          make(chan configUpdate, 1),
				collectorStatusCh: make(chan *status.AggregateStatus),
				componentStateCh:  make(chan []runtime.ComponentComponentState, 1),
				doneChan:          make(chan struct{}),
				collectorRunErr:   make(chan error),
				recoveryTimer:     tc.restarter,
				stopTimeout:       waitTimeForStop,
				agentInfo:         &info.AgentInfo{},
			}

			executionMode, err := tc.execModeFn(m.collectorRunErr)
			require.NoError(t, err, "failed to create execution mode")
			testExecutionMode := &testExecution{exec: executionMode}
			m.execution = testExecutionMode

			eListener := &EventListener{}
			defer func() {
				if !t.Failed() {
					return
				}
				t.Logf("latest received err: %s", eListener.getError())
				t.Logf("latest received status: %s", statusToYaml(eListener.getCollectorStatus()))
				for _, entry := range obs.All() {
					t.Logf("%+v", entry)
				}
			}()

			runWg := sync.WaitGroup{}
			runWg.Add(1)
			go func() {
				defer runWg.Done()
				if !tc.skipListeningErrors {
					eListener.Listen(ctx, m.Errors(), m.WatchCollector(), m.WatchComponents())
				} else {
					eListener.Listen(ctx, nil, m.WatchCollector(), m.WatchComponents())
				}
			}()

			var runErr error
			runWg.Add(1)
			managerCtx, managerCancel := context.WithCancel(ctx)
			go func() {
				defer runWg.Done()
				runErr = m.Run(managerCtx)
			}()

			tc.testFn(t, m, eListener, testExecutionMode, managerCancel, m.collectorRunErr)

			cancel()
			runWg.Wait()
			if !errors.Is(runErr, context.Canceled) {
				t.Errorf("otel manager returned unexpected error: %v", runErr)
			}
		})
	}
}

func TestOTelManager_Logging(t *testing.T) {
	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "..", "..", "..", "..", "internal", "edot", "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const waitTimeForStop = 30 * time.Second

	base, obs := loggertest.New("otel")
	l, _ := loggertest.New("otel-manager")

	for _, tc := range []struct {
		name       string
		execModeFn func(collectorRunErr chan error) (collectorExecution, error)
	}{
		{
			name: "subprocess execution",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), 0, 0)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// the execution mode passed here is overridden below so it is irrelevant
			m, err := NewOTelManager(l, logp.InfoLevel, base, &info.AgentInfo{}, nil, nil, waitTimeForStop)
			require.NoError(t, err, "could not create otel manager")

			executionMode, err := tc.execModeFn(m.collectorRunErr)
			require.NoError(t, err, "failed to create execution mode")
			testExecutionMode := &testExecution{exec: executionMode}
			m.execution = testExecutionMode

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
			m.Update(cfg, nil, logp.InfoLevel, nil)

			// the collector should log to the base logger
			assert.EventuallyWithT(t, func(collect *assert.CollectT) {
				logs := obs.All()
				require.NotEmpty(collect, logs, "Logs should not be empty")
				firstMessage := logs[0].Message
				assert.Equal(collect, "Internal metrics telemetry disabled", firstMessage)
			}, time.Second*10, time.Second)
		})
	}
}

func TestOTelManager_Ports(t *testing.T) {
	ports, err := findRandomTCPPorts(2)
	require.NoError(t, err)
	healthCheckPort, metricsPort := ports[0], ports[1]
	agentCollectorConfig := configuration.CollectorConfig{
		HealthCheckConfig: configuration.CollectorHealthCheckConfig{
			Endpoint: fmt.Sprintf("http://localhost:%d", healthCheckPort),
		},
		TelemetryConfig: configuration.CollectorTelemetryConfig{
			Endpoint: fmt.Sprintf("http://localhost:%d", metricsPort),
		},
	}

	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "..", "..", "..", "..", "internal", "edot", "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	const waitTimeForStop = 30 * time.Second

	for _, tc := range []struct {
		name               string
		execModeFn         func(collectorRunErr chan error) (collectorExecution, error)
		healthCheckEnabled bool
	}{
		{
			name: "subprocess execution",
			execModeFn: func(collectorRunErr chan error) (collectorExecution, error) {
				hcUUID, err := uuid.NewV4()
				if err != nil {
					return nil, fmt.Errorf("cannot generate UUID: %w", err)
				}
				return newSubprocessExecution(testBinary, hcUUID.String(), metricsPort, healthCheckPort)
			},
			healthCheckEnabled: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, obs := loggertest.New("otel")
			l, _ := loggertest.New("otel-manager")
			ctx := t.Context()

			t.Cleanup(func() {
				if t.Failed() {
					for _, log := range obs.All() {
						t.Logf("%+v", log)
					}
				}
			})

			// the execution mode passed here is overridden below so it is irrelevant
			m, err := NewOTelManager(
				l,
				logp.InfoLevel,
				base,
				&info.AgentInfo{},
				&agentCollectorConfig,
				nil,
				waitTimeForStop,
			)
			require.NoError(t, err, "could not create otel manager")

			executionMode, err := tc.execModeFn(m.collectorRunErr)
			require.NoError(t, err, "failed to create execution mode")
			testExecutionMode := &testExecution{exec: executionMode}
			m.execution = testExecutionMode

			go func() {
				err := m.Run(ctx)
				assert.ErrorIs(t, err, context.Canceled, "otel manager should be cancelled")
			}()

			go func() {
				for {
					select {
					case colErr := <-m.Errors():
						require.NoError(t, colErr, "otel manager should not return errors")
					case <-m.WatchComponents(): // ensure we receive component updates
					case <-ctx.Done():
						return
					}
				}
			}()

			cfg := confmap.NewFromStringMap(testConfig)
			cfg.Delete("service::telemetry::metrics::level") // change this to default
			m.Update(cfg, nil, logp.InfoLevel, nil)

			// wait until status reflects the config update
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				select {
				case collectorStatus := <-m.WatchCollector():
					require.NotNil(collect, collectorStatus, "collector status should not be nil")
					assert.Equal(collect, componentstatus.StatusOK, collectorStatus.Status())
					assert.NotEmpty(collect, collectorStatus.ComponentStatusMap)
				case <-ctx.Done():
					require.NoError(collect, ctx.Err())
				}
			}, time.Second*10, time.Second)

			// the collector should expose its status and metrics on the set ports
			healthCheckUrl := fmt.Sprintf("http://localhost:%d%s", healthCheckPort, healthCheckHealthStatusPath)
			metricsUrl := fmt.Sprintf("http://localhost:%d/metrics", metricsPort)
			urlsToCheck := []string{metricsUrl}
			if tc.healthCheckEnabled {
				urlsToCheck = append(urlsToCheck, healthCheckUrl)
			}
			for _, url := range urlsToCheck {
				assert.EventuallyWithT(t, func(collect *assert.CollectT) {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
					assert.NoError(collect, err)
					resp, err := http.DefaultClient.Do(req)
					require.NoError(collect, err)
					defer func() {
						_ = resp.Body.Close()
					}()
					assert.Equal(collect, http.StatusOK, resp.StatusCode)
				}, time.Second*10, time.Second)
			}
		})
	}
}

// TestOTelManager_PortConflict test verifies that the collector restarts and tries new ports if it encounters a port
// conflict.
func TestOTelManager_PortConflict(t *testing.T) {
	// switch the net.Listen implementation with one that returns test listeners that ignore the Close call the first
	// two times
	var timesCalled int
	var mx sync.Mutex
	netListen = func(network string, address string) (net.Listener, error) {
		mx.Lock()
		defer mx.Unlock()
		l, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		if timesCalled < 2 {
			// only actually close the listener after test completion, freeing the port
			t.Cleanup(func() {
				assert.NoError(t, l.Close())
			})
			// this listener won't free the port even after Close is called, leading to port binding conflicts later
			// in the test
			l = &fakeCloseListener{inner: l}
		}
		timesCalled++
		return l, err
	}
	t.Cleanup(func() {
		netListen = net.Listen
	})

	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "..", "..", "..", "..", "internal", "edot", "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	const waitTimeForStop = 30 * time.Second

	base, obs := loggertest.New("base")
	l := base.Named("otel-manager")
	ctx := t.Context()

	t.Cleanup(func() {
		if t.Failed() {
			for _, log := range obs.All() {
				t.Logf("%+v", log)
			}
		}
	})

	// the execution mode passed here is overridden below so it is irrelevant
	m, err := NewOTelManager(
		l,
		logp.InfoLevel,
		base,
		&info.AgentInfo{},
		nil,
		nil,
		waitTimeForStop,
	)
	require.NoError(t, err, "could not create otel manager")
	executionMode, err := newSubprocessExecution(testBinary, strings.TrimPrefix(m.healthCheckExtID, "extension:healthcheckv2/"), 0, 0)
	require.NoError(t, err, "could not create subprocess execution mode")
	m.execution = executionMode

	go func() {
		err := m.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled, "otel manager should be cancelled")
	}()

	go func() {
		for {
			select {
			case <-m.Errors():
			case <-m.WatchComponents(): // ensure we receive component updates
			case <-ctx.Done():
				return
			}
		}
	}()

	cfg := confmap.NewFromStringMap(testConfig)
	cfg.Delete("service::telemetry::metrics::level") // change this to default

	// no retries, collector is not running
	assert.Equal(t, uint32(0), m.recoveryRetries.Load())

	m.Update(cfg, nil, logp.InfoLevel, nil)

	// wait until status reflects the config update
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		select {
		case collectorStatus := <-m.WatchCollector():
			require.NotNil(collect, collectorStatus, "collector status should not be nil")
			assert.Equal(collect, componentstatus.StatusOK, collectorStatus.Status())
			assert.NotEmpty(collect, collectorStatus.ComponentStatusMap)
		case <-ctx.Done():
			require.NoError(collect, ctx.Err())
		}
	}, time.Second*10, time.Second)

	// collector must have retried exactly once
	assert.Equal(t, uint32(1), m.recoveryRetries.Load())
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
	var (
		commonAgentInfo                  = &info.AgentInfo{}
		commonBeatMonitoringConfigGetter = mockBeatMonitoringConfigGetter
		testComp                         = testComponent("test-component")
		invalidLogpLevel                 = logp.DebugLevel - 1
		testOtelConfigLevel              = logp.InfoLevel
		configUpdateLevel                = logp.WarnLevel
	)

	tests := []struct {
		name                string
		collectorCfg        *confmap.Conf
		components          []component.Component
		expectedKeys        []string
		expectedErrorString string
		expectedLogLevel    logp.Level
	}{
		{
			name:             "nil config returns nil",
			collectorCfg:     nil,
			components:       nil,
			expectedLogLevel: invalidLogpLevel,
		},
		{
			name:             "empty config returns empty config",
			collectorCfg:     nil,
			components:       nil,
			expectedKeys:     []string{},
			expectedLogLevel: invalidLogpLevel,
		},
		{
			name:             "collector config only",
			collectorCfg:     confmap.NewFromStringMap(testConfig),
			components:       nil,
			expectedKeys:     []string{"receivers", "exporters", "service", "processors"},
			expectedLogLevel: testOtelConfigLevel,
		},
		{
			name:             "components only",
			collectorCfg:     nil,
			components:       []component.Component{testComp},
			expectedKeys:     []string{"receivers", "exporters", "service"},
			expectedLogLevel: configUpdateLevel,
		},
		{
			name:             "collector config with log level config and components",
			collectorCfg:     confmap.NewFromStringMap(testConfig),
			components:       []component.Component{testComp},
			expectedKeys:     []string{"receivers", "exporters", "service", "processors"},
			expectedLogLevel: testOtelConfigLevel,
		},
		{
			name:             "collector config without log level config and components",
			collectorCfg:     confmap.NewFromStringMap(testConfigNoLogLevel),
			components:       []component.Component{testComp},
			expectedKeys:     []string{"receivers", "exporters", "service", "processors"},
			expectedLogLevel: configUpdateLevel,
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
			expectedLogLevel:    -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgUpdate := configUpdate{
				collectorCfg:  tt.collectorCfg,
				components:    tt.components,
				agentLogLevel: configUpdateLevel,
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

			// assert log level provided by user is given precedence.
			if tt.expectedLogLevel > invalidLogpLevel {
				lvl, err := newLogLevelAfterConfigUpdate(cfgUpdate, result)
				assert.NoError(t, err, "newLogLevelAfterConfigUpdate() call failed")
				assert.Equal(t, tt.expectedLogLevel, lvl)
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
					"extensions": {
						Event: componentstatus.NewEvent(componentstatus.StatusOK),
						ComponentStatusMap: map[string]*status.AggregateStatus{
							"extension:beatsauth/test": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"extension:elastic_diagnostics/test": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
							"extension:healthcheckv2/uuid": {
								Event: componentstatus.NewEvent(componentstatus.StatusOK),
							},
						},
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
						Message: "Healthy",
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
				managerLogger:          newTestLogger(),
				components:             tt.components,
				healthCheckExtID:       "extension:healthcheckv2/uuid",
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
				managerLogger:          newTestLogger(),
				currentComponentStates: tt.currentComponentStates,
			}

			result := mgr.processComponentStates(tt.inputComponentStates)

			assert.ElementsMatch(t, tt.expectedOutputStates, result)
			assert.Equal(t, tt.expectedCurrentStatesAfter, mgr.currentComponentStates)
		})
	}
}

// TestOTelManagerEndToEnd tests the full lifecycle of the OTelManager including configuration updates, status updates,
// and error handling. This test only uses synthetic errors and statuses, and the mock execution used doesn't behave
// exactly like the real executions.
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
		managerLogger:              testLogger,
		collectorLogger:            testLogger,
		errCh:                      make(chan error, 1), // holds at most one error
		updateCh:                   make(chan configUpdate, 1),
		collectorStatusCh:          make(chan *status.AggregateStatus, 1),
		componentStateCh:           make(chan []runtime.ComponentComponentState, 5),
		doneChan:                   make(chan struct{}),
		recoveryTimer:              newRestarterNoop(),
		execution:                  execution,
		agentInfo:                  agentInfo,
		beatMonitoringConfigGetter: beatMonitoringConfigGetter,
		collectorRunErr:            make(chan error),
	}

	// Start manager in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
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
		mgr.Update(collectorCfg, nil, logp.InfoLevel, nil)
		select {
		case <-collectorStarted:
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector config update")
		}
		expectedCfg := confmap.NewFromStringMap(collectorCfg.ToStringMap())
		assert.NoError(t, injectDiagnosticsExtension(expectedCfg))
		assert.NoError(t, addCollectorMetricsReader(expectedCfg))
		assert.Equal(t, expectedCfg, execution.cfg)

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

		componentStates, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(t, err)
		assert.Empty(t, componentStates)
		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		assert.Equal(t, otelStatus, collectorStatus)
	})

	t.Run("component config is passed down to the otel manager", func(t *testing.T) {
		mgr.Update(collectorCfg, nil, logp.InfoLevel, components)
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
	})

	t.Run("empty collector config leaves the component config running", func(t *testing.T) {
		mgr.Update(nil, nil, logp.InfoLevel, components)
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

		componentState, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(t, err)
		require.NotNil(t, componentState)
		require.Len(t, componentState, 1)
		assert.Equal(t, componentState[0].Component, testComp)

		collectorStatus, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchCollector(), mgr.Errors())
		require.NoError(t, err)
		require.NotNil(t, collectorStatus)
		assert.Len(t, collectorStatus.ComponentStatusMap, 0)
	})

	t.Run("collector execution error is passed as status not error", func(t *testing.T) {
		collectorErr := errors.New("collector error")

		var err error
		var aggStatus *status.AggregateStatus
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case aggStatus = <-mgr.WatchCollector():
				case <-mgr.WatchComponents():
					// don't block (ignored for test)
				case e := <-mgr.Errors():
					err = e
					if err != nil {
						// only return if real error (nil is just clearing the error state)
						return
					}
				case <-time.After(time.Second):
					// didn't get an error (good!)
					return
				}
			}
		}()

		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for collector status update")
		case execution.errCh <- collectorErr:
		}
		wg.Wait()

		// should not come in as an error
		require.Nil(t, err, "got unexpected error from the collector execution")

		// should have a fatal error in status
		require.NotNil(t, aggStatus)
		assert.Equal(t, aggStatus.Status(), componentstatus.StatusFatalError)
	})
}

// TestManagerAlwaysEmitsStoppedStatesForComponents checks that the manager always emits a STOPPED state for a component
// at least once, even if we're slow to retrieve the state. This is part of the contract with the coordinator.
func TestManagerAlwaysEmitsStoppedStatesForComponents(t *testing.T) {
	// Setup test logger and dependencies
	testLogger, _ := loggertest.New("test")
	beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter
	collectorStarted := make(chan struct{})

	execution := &mockExecution{
		collectorStarted: collectorStarted,
	}

	// Create manager with test dependencies
	mgr, err := NewOTelManager(
		testLogger,
		logp.InfoLevel,
		testLogger,
		&info.AgentInfo{},
		nil,
		beatMonitoringConfigGetter,
		time.Second,
	)
	require.NoError(t, err)
	mgr.recoveryTimer = newRestarterNoop()
	mgr.execution = execution

	// Start manager in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	go func() {
		err := mgr.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	}()

	testComp := testComponent("test")
	components := []component.Component{testComp}
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
	// start the collector by giving it a mock config
	mgr.Update(nil, nil, logp.InfoLevel, components)
	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for collector status update")
	case <-execution.collectorStarted:
	}

	// send the status from the execution
	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for collector status update")
	case execution.statusCh <- otelStatus:
	}

	// verify we get the component running state from the manager
	componentStates, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
	require.NoError(t, err)
	require.NotNil(t, componentStates)
	require.Len(t, componentStates, 1)
	componentState := componentStates[0]
	assert.Equal(t, componentState.State.State, client.UnitStateHealthy)

	// stop the component by sending a nil config
	mgr.Update(nil, nil, logp.InfoLevel, nil)

	// then send a nil status, indicating the collector is not running the component anymore
	// do this a few times to see if the STOPPED state isn't lost along the way
	for range 3 {
		reportCollectorStatus(ctx, execution.statusCh, nil)
		time.Sleep(time.Millisecond * 100) //  TODO: Replace this with synctest after we upgrade to Go 1.25
	}

	// verify that we get a STOPPED state for the component
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		componentStates, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(collect, err)
		require.NotNil(collect, componentStates)
		require.Len(collect, componentStates, 1)
		componentState := componentStates[0]
		assert.Equal(collect, componentState.State.State, client.UnitStateStopped)
	}, time.Millisecond, time.Second*5)
}

func TestManagerEmitsStartingStatesWhenHealthcheckIsUnavailable(t *testing.T) {
	testLogger, _ := loggertest.New("test")
	agentInfo := &info.AgentInfo{}
	beatMonitoringConfigGetter := mockBeatMonitoringConfigGetter
	collectorStarted := make(chan struct{})

	execution := &mockExecution{
		collectorStarted: collectorStarted,
	}

	// Create manager with test dependencies
	mgr, err := NewOTelManager(
		testLogger,
		logp.InfoLevel,
		testLogger,
		agentInfo,
		nil,
		beatMonitoringConfigGetter,
		time.Second,
	)
	require.NoError(t, err)
	mgr.recoveryTimer = newRestarterNoop()
	mgr.execution = execution

	// Start manager in a goroutine
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	go func() {
		err := mgr.Run(ctx)
		assert.ErrorIs(t, err, context.Canceled)
	}()

	testComp := testComponent("test")
	components := []component.Component{testComp}
	otelStatus := &status.AggregateStatus{
		Event: componentstatus.NewEvent(componentstatus.StatusStarting),
	}
	// start the collector by giving it a mock config
	mgr.Update(nil, nil, logp.InfoLevel, components)
	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for collector status update")
	case <-execution.collectorStarted:
	}

	// send the status from the execution
	select {
	case <-ctx.Done():
		t.Fatal("timeout waiting for collector status update")
	case execution.statusCh <- otelStatus:
	}

	// verify we get the component Starting state from the manager
	componentStates, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
	require.NoError(t, err)
	require.NotNil(t, componentStates)
	require.Len(t, componentStates, 1)
	componentState := componentStates[0]
	assert.Equal(t, componentState.State.State, client.UnitStateStarting)
	assert.Equal(t, componentState.State.Message, "STARTING")

	// stop the component by sending a nil config
	mgr.Update(nil, nil, logp.InfoLevel, nil)

	// then send a nil status, indicating the collector is not running the component anymore
	// do this a few times to see if the STOPPED state isn't lost along the way
	for range 3 {
		reportCollectorStatus(ctx, execution.statusCh, nil)
		time.Sleep(time.Millisecond * 100) //  TODO: Replace this with synctest after we upgrade to Go 1.25
	}

	// verify that we get a STOPPED state for the component
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		componentStates, err := getFromChannelOrErrorWithContext(t, ctx, mgr.WatchComponents(), mgr.Errors())
		require.NoError(collect, err)
		require.NotNil(collect, componentStates)
		require.Len(collect, componentStates, 1)
		componentState := componentStates[0]
		assert.Equal(collect, componentState.State.State, client.UnitStateStopped)
	}, time.Millisecond, time.Second*5)
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

func TestCalculateConfmapHash(t *testing.T) {
	t.Run("nil config returns zero", func(t *testing.T) {
		hash, err := calculateConfmapHash(nil)
		require.NoError(t, err)
		assert.Equal(t, []byte(nil), hash)
	})

	t.Run("same value gives same result", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"key1": "value1",
			"key2": 123,
		})
		hash1, err := calculateConfmapHash(conf)
		require.NoError(t, err)
		hash2, err := calculateConfmapHash(conf)
		require.NoError(t, err)
		assert.Equal(t, hash1, hash2)
	})

	t.Run("different values give different results", func(t *testing.T) {
		conf1 := confmap.NewFromStringMap(map[string]any{
			"key1": "value1",
		})
		hash1, err := calculateConfmapHash(conf1)
		require.NoError(t, err)

		conf2 := confmap.NewFromStringMap(map[string]any{
			"key1": "value2",
		})
		hash2, err := calculateConfmapHash(conf2)
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("list of maps is processed correctly", func(t *testing.T) {
		conf1 := confmap.NewFromStringMap(map[string]any{
			"items": []any{
				map[string]any{"name": "A", "value": 1},
				map[string]any{"name": "B", "value": 2},
			},
		})
		hash1, err := calculateConfmapHash(conf1)
		require.NoError(t, err)

		t.Run("same list of maps gives same hash", func(t *testing.T) {
			conf2 := confmap.NewFromStringMap(map[string]any{
				"items": []any{
					map[string]any{"name": "A", "value": 1},
					map[string]any{"name": "B", "value": 2},
				},
			})
			hash2, err := calculateConfmapHash(conf2)
			require.NoError(t, err)
			assert.Equal(t, hash1, hash2)
		})

		t.Run("different order in list gives different hash", func(t *testing.T) {
			conf3 := confmap.NewFromStringMap(map[string]any{
				"items": []any{
					map[string]any{"name": "B", "value": 2},
					map[string]any{"name": "A", "value": 1},
				},
			})
			hash3, err := calculateConfmapHash(conf3)
			require.NoError(t, err)
			assert.NotEqual(t, hash1, hash3)
		})
	})
}

func TestOTelManager_maybeUpdateMergedConfig(t *testing.T) {
	t.Run("initial config", func(t *testing.T) {
		m := &OTelManager{}
		conf := confmap.NewFromStringMap(testConfig)

		updated, err := m.maybeUpdateMergedConfig(conf)

		require.NoError(t, err)
		assert.True(t, updated)
		assert.Equal(t, conf, m.mergedCollectorCfg)
		assert.NotEqual(t, uint64(0), m.mergedCollectorCfgHash)
	})

	t.Run("same config", func(t *testing.T) {
		conf := confmap.NewFromStringMap(testConfig)
		hash, err := calculateConfmapHash(conf)
		require.NoError(t, err)

		m := &OTelManager{
			mergedCollectorCfg:     conf,
			mergedCollectorCfgHash: hash,
		}

		updated, err := m.maybeUpdateMergedConfig(conf)

		require.NoError(t, err)
		assert.False(t, updated)
		assert.Equal(t, conf, m.mergedCollectorCfg)
		assert.Equal(t, hash, m.mergedCollectorCfgHash)
	})

	t.Run("different config", func(t *testing.T) {
		conf1 := confmap.NewFromStringMap(map[string]any{"key": "value1"})
		hash1, err := calculateConfmapHash(conf1)
		require.NoError(t, err)

		m := &OTelManager{
			mergedCollectorCfg:     conf1,
			mergedCollectorCfgHash: hash1,
		}

		conf2 := confmap.NewFromStringMap(map[string]any{"key": "value2"})
		hash2, err := calculateConfmapHash(conf2)
		require.NoError(t, err)

		updated, err := m.maybeUpdateMergedConfig(conf2)

		require.NoError(t, err)
		assert.True(t, updated)
		assert.Equal(t, conf2, m.mergedCollectorCfg)
		assert.Equal(t, hash2, m.mergedCollectorCfgHash)
		assert.NotEqual(t, hash1, m.mergedCollectorCfgHash)
	})

	t.Run("hashing error with previous config", func(t *testing.T) {
		conf1 := confmap.NewFromStringMap(map[string]any{"key": "value1"})
		hash1, err := calculateConfmapHash(conf1)
		require.NoError(t, err)

		m := &OTelManager{
			mergedCollectorCfg:     conf1,
			mergedCollectorCfgHash: hash1,
		}

		badConf := confmap.NewFromStringMap(map[string]any{"bad": make(chan int)})
		updated, err := m.maybeUpdateMergedConfig(badConf)

		require.Error(t, err)
		assert.True(t, updated, "update should proceed on hashing error")
		assert.Equal(t, badConf, m.mergedCollectorCfg)
		assert.Equal(t, []byte(nil), m.mergedCollectorCfgHash)
	})

	t.Run("hashing error with no previous config", func(t *testing.T) {
		m := &OTelManager{}

		badConf := confmap.NewFromStringMap(map[string]any{"bad": make(chan int)})
		updated, err := m.maybeUpdateMergedConfig(badConf)

		require.Error(t, err)
		assert.True(t, updated, "update should proceed on hashing error, even with no previous config")
		assert.Equal(t, badConf, m.mergedCollectorCfg)
		assert.Equal(t, []byte(nil), m.mergedCollectorCfgHash)
	})
}

func TestAddCollectorMetricsPort(t *testing.T) {
	expectedReader := map[string]any{
		"pull": map[string]any{
			"exporter": map[string]any{
				"prometheus": map[string]any{
					"host":                "localhost",
					"port":                fmt.Sprintf("${env:%s}", OtelCollectorMetricsPortEnvVarName),
					"without_scope_info":  true,
					"without_units":       true,
					"without_type_suffix": true,
				},
			},
		},
	}
	otelConfigWithReaders := func(readers any) *confmap.Conf {
		baseConf := confmap.NewFromStringMap(testConfig)
		err := baseConf.Merge(confmap.NewFromStringMap(map[string]any{
			"service": map[string]any{
				"telemetry": map[string]any{
					"metrics": map[string]any{
						"readers": readers,
					},
				},
			},
		}))
		require.NoError(t, err)
		return baseConf
	}

	t.Run("readers does not exist", func(t *testing.T) {
		conf := otelConfigWithReaders(nil)
		err := addCollectorMetricsReader(conf)
		require.NoError(t, err)

		readers := conf.Get("service::telemetry::metrics::readers")
		require.NotNil(t, readers)
		readersList, ok := readers.([]any)
		require.True(t, ok)
		require.Len(t, readersList, 1)

		assert.Equal(t, expectedReader, readersList[0])
	})

	t.Run("readers is an empty list", func(t *testing.T) {
		conf := otelConfigWithReaders([]any{})
		err := addCollectorMetricsReader(conf)
		require.NoError(t, err)

		readers := conf.Get("service::telemetry::metrics::readers")
		require.NotNil(t, readers)
		readersList, ok := readers.([]any)
		require.True(t, ok)
		require.Len(t, readersList, 1)

		assert.Equal(t, expectedReader, readersList[0])
	})

	t.Run("readers has existing items", func(t *testing.T) {
		existingReader := map[string]any{"foo": "bar"}
		conf := otelConfigWithReaders([]any{existingReader})
		err := addCollectorMetricsReader(conf)
		require.NoError(t, err)

		readers := conf.Get("service::telemetry::metrics::readers")
		require.NotNil(t, readers)
		readersList, ok := readers.([]any)
		require.True(t, ok)
		require.Len(t, readersList, 2)

		assert.Equal(t, existingReader, readersList[0])
		assert.Equal(t, expectedReader, readersList[1])
	})

	t.Run("readers is not a list", func(t *testing.T) {
		conf := otelConfigWithReaders("not a list")
		err := addCollectorMetricsReader(conf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "couldn't convert value of service::telemetry::metrics::readers to a list")
	})
}

// fakeCloseListener is a wrapper around a net.Listener that ignores the Close() method. This is used in a very particular
// port conflict test to ensure ports are not unbound while the otel collector tries to use them.
type fakeCloseListener struct {
	inner net.Listener
}

func (t *fakeCloseListener) Accept() (net.Conn, error) {
	return t.inner.Accept()
}

func (t *fakeCloseListener) Close() error {
	return nil
}

func (t *fakeCloseListener) Addr() net.Addr {
	return t.inner.Addr()
}
