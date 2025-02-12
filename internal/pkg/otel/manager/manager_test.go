// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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
			"otlp": map[string]interface{}{
				"protocols": map[string]interface{}{
					"grpc": map[string]interface{}{
						"endpoint": "0.0.0.0:4317",
					},
				},
			},
		},
		"processors": map[string]interface{}{
			"batch": map[string]interface{}{},
		},
		"exporters": map[string]interface{}{
			"otlp": map[string]interface{}{
				"endpoint": "otelcol:4317",
			},
		},
		"service": map[string]interface{}{
			"pipelines": map[string]interface{}{
				"traces": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
				"metrics": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
				"logs": map[string]interface{}{
					"receivers":  []string{"otlp"},
					"processors": []string{"batch"},
					"exporters":  []string{"otlp"},
				},
			},
		},
	}
)

func TestOTelManager_Run(t *testing.T) {
	t.Skip("Flaky test") // https://github.com/elastic/elastic-agent/issues/6119
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
			if latest == nil || latest.Event.Status() != componentstatus.StatusOK {
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
			t.Fatalf("otel collector never got healthy: %+v (latest err: %v)", lastStatus, lastErr)
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
		require.ErrorIs(t, err, context.Canceled, "otel manager should be cancelled")
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

	cfg := confmap.New() // invalid config
	m.Update(cfg)
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
