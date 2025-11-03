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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/confmap"

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

<<<<<<< HEAD
=======
type testExecution struct {
	mtx    sync.Mutex
	exec   collectorExecution
	handle collectorHandle
}

func (e *testExecution) startCollector(ctx context.Context, baseLogger *logger.Logger, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus, forceFetchStatusCh chan struct{}) (collectorHandle, error) {
	e.mtx.Lock()
	defer e.mtx.Unlock()

	var err error
	e.handle, err = e.exec.startCollector(ctx, baseLogger, logger, cfg, errCh, statusCh, forceFetchStatusCh)
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
		require.Equal(collect, componentstatus.StatusOK, latestStatus.Value().Status())
	}, 60*time.Second, 1*time.Second, "otel collector never got healthy")
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

>>>>>>> 83880d318 ([beatsreceivers] add option to mute exporter status (#10890))
func TestOTelManager_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, _ := loggertest.New("otel")
	l, _ := loggertest.New("otel-manager")
	m := NewOTelManager(l, base)

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
	base, _ := loggertest.New("otel")
	l, _ := loggertest.New("otel-manager")
	m := NewOTelManager(l, base)

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

func TestOTelManager_Logging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, obs := loggertest.New("otel")
	l, _ := loggertest.New("otel-manager")
	m := NewOTelManager(l, base)

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

	cfg := confmap.NewFromStringMap(testConfig)
	m.Update(cfg)

	// the collector should log to the base logger
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		logs := obs.All()
		require.NotEmpty(collect, logs, "Logs should not be empty")
		firstMessage := logs[0].Message
		assert.Equal(collect, "Internal metrics telemetry disabled", firstMessage)
	}, time.Second*10, time.Second)
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
