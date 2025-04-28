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
