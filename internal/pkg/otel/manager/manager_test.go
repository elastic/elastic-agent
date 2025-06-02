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

	"github.com/elastic/elastic-agent/pkg/core/logger"

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
		skipListeningErrors bool
		testFn              func(t *testing.T, m *OTelManager, e *EventListener)
	}{
		{
			name: "collector config updates",
			testFn: func(t *testing.T, m *OTelManager, e *EventListener) {
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
			},
		},
		{
			name: "collector stopped gracefully outside manager",
			testFn: func(t *testing.T, m *OTelManager, e *EventListener) {
				var handle *procHandle
				defer func() {
					startSupervisedCollectorFn = startSupervisedCollector
				}()
				startSupervisedCollectorFn = func(ctx context.Context, logger *logger.Logger, collectorPath string, collectorArgs []string, cfg *confmap.Conf, processErrCh chan error, statusCh chan *status.AggregateStatus) (*procHandle, error) {
					var err error
					handle, err = startSupervisedCollector(ctx, logger, collectorPath, collectorArgs, cfg, processErrCh, statusCh)
					return handle, err
				}

				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// stop it, this should be restarted by the manager
				updateTime = time.Now()
				handle.Stop(t.Context())
				e.EnsureHealthy(t, updateTime)

				// no configuration should stop the runner
				updateTime = time.Now()
				m.Update(nil)
				e.EnsureOffWithoutError(t, updateTime)
			},
		},
		{
			name: "collector killed outside manager",
			testFn: func(t *testing.T, m *OTelManager, e *EventListener) {
				defer func() {
					startSupervisedCollectorFn = startSupervisedCollector
				}()
				var handle *procHandle
				startSupervisedCollectorFn = func(ctx context.Context, logger *logger.Logger, collectorPath string, collectorArgs []string, cfg *confmap.Conf, processErrCh chan error, statusCh chan *status.AggregateStatus) (*procHandle, error) {
					var err error
					handle, err = startSupervisedCollector(ctx, logger, collectorPath, collectorArgs, cfg, processErrCh, statusCh)
					return handle, err
				}

				// ensure that it got healthy
				cfg := confmap.NewFromStringMap(testConfig)
				updateTime := time.Now()
				m.Update(cfg)
				e.EnsureHealthy(t, updateTime)

				// kill it
				updateTime = time.Now()
				require.NoError(t, handle.processInfo.Kill(), "failed to kill collector process")
				e.EnsureOffWithError(t, updateTime)
			},
		},
		{
			name:                "collector invalid config",
			skipListeningErrors: true,
			testFn: func(t *testing.T, m *OTelManager, e *EventListener) {
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
				logger:              l,
				baseLogger: base,
				errCh:               make(chan error, 1), // holds at most one error
				cfgCh:               make(chan *confmap.Conf),
				statusCh:            make(chan *status.AggregateStatus),
				doneChan:            make(chan struct{}),
				collectorBinaryPath: testBinary,
				collectorBinaryArgs: []string{""},
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

			tc.testFn(t, m, eListener)

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
	m, err := NewOTelManager(l, base)
	require.NoError(t, err, "failed to create otel manager")

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
