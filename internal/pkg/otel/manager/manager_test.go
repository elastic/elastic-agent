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

type EventTime[T interface{}] struct {
	time time.Time
	val  T
}

func (t *EventTime[T]) Before(u time.Time) bool {
	return t != nil && t.time.Before(u)
}

func (t *EventTime[T]) Value() T {
	if t == nil {
		var zero T
		return zero
	}
	return t.val
}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := loggertest.New("otel")
	m := &OTelManager{
		logger:              l,
		errCh:               make(chan error, 1), // holds at most one error
		cfgCh:               make(chan *confmap.Conf),
		statusCh:            make(chan *status.AggregateStatus),
		doneChan:            make(chan struct{}),
		collectorBinaryPath: testBinary,
		collectorBinaryArgs: []string{""},
	}

	var errMx sync.Mutex
	var err *EventTime[error]
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e := <-m.Errors():
				errMx.Lock()
				err = &EventTime[error]{time: time.Now(), val: e}
				errMx.Unlock()
			}
		}
	}()
	getLatestErr := func() *EventTime[error] {
		errMx.Lock()
		defer errMx.Unlock()
		return err
	}

	var latestMx sync.Mutex
	var latest *EventTime[*status.AggregateStatus]
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-m.Watch():
				latestMx.Lock()
				latest = &EventTime[*status.AggregateStatus]{val: c, time: time.Now()}
				latestMx.Unlock()
			}
		}
	}()
	getLatestStatus := func() *EventTime[*status.AggregateStatus] {
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

	ensureHealthy := func(u time.Time) {
		if !assert.Eventuallyf(t, func() bool {
			if latestErr := getLatestErr(); latestErr == nil || latestErr.Before(u) || latestErr.Value() != nil {
				return false
			}
			if latestStatus := getLatestStatus(); latestStatus == nil || latestStatus.Value() == nil || latestStatus.Before(u) || latestStatus.Value().Status() != componentstatus.StatusOK {
				return false
			}
			return true
		}, 60*time.Second, 1*time.Second, "otel collector never got healthy") {
			lastStatus := getLatestStatus().Value()
			lastErr := getLatestErr().Value()

			// never got healthy, stop the manager and wait for it to end
			cancel()
			runWg.Wait()

			// if a run error happened then report that
			if !errors.Is(runErr, context.Canceled) {
				t.Fatalf("otel manager never got healthy and the otel manager returned unexpected error: %v (latest status: %+v) (latest err: %v)", runErr, lastStatus, lastErr)
			}
			t.Fatalf("otel collector never got healthy: %s (latest err: %v)", statusToYaml(lastStatus), lastErr)
		}
		require.NoError(t, getLatestErr().Value(), "runtime errored")
	}

	ensureOff := func(u time.Time) {
		require.Eventuallyf(t, func() bool {
			if latestErr := getLatestErr(); latestErr == nil || latestErr.Before(u) || latestErr.Value() != nil {
				return false
			}
			if latestStatus := getLatestStatus(); latestStatus == nil || latestStatus.Before(u) || latestStatus.Value() != nil {
				return false
			}
			return true
		}, 60*time.Second, 1*time.Second, "otel collector never stopped")
		require.NoError(t, getLatestErr().Value(), "runtime errored")
	}

	// ensure that it got healthy
	cfg := confmap.NewFromStringMap(testConfig)
	updateTime := time.Now()
	m.Update(cfg)
	ensureHealthy(updateTime)

	// trigger update (no config compare is due externally to otel collector)
	updateTime = time.Now()
	m.Update(cfg)
	ensureHealthy(updateTime)

	// no configuration should stop the runner
	updateTime = time.Now()
	m.Update(nil)
	ensureOff(updateTime)

	cancel()
	runWg.Wait()
	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("otel manager returned unexpected error: %v", runErr)
	}
}

func TestOTelManager_ConfigError(t *testing.T) {
	wd, erWd := os.Getwd()
	require.NoError(t, erWd, "cannot get working directory")

	testBinary := filepath.Join(wd, "testing", "testing")
	require.FileExists(t, testBinary, "testing binary not found")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l, _ := loggertest.New("otel")
	m := &OTelManager{
		logger:              l,
		errCh:               make(chan error, 1), // holds at most one error
		cfgCh:               make(chan *confmap.Conf),
		statusCh:            make(chan *status.AggregateStatus),
		doneChan:            make(chan struct{}),
		collectorBinaryPath: testBinary,
		collectorBinaryArgs: []string{""},
	}

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
