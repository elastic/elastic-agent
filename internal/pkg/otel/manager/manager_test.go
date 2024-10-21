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

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"github.com/stretchr/testify/require"
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
		"extensions": map[string]interface{}{
			"health_check": map[string]interface{}{},
			"pprof":        map[string]interface{}{},
		},
		"service": map[string]interface{}{
			"extensions": []interface{}{"health_check", "pprof"},
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
		require.Eventuallyf(t, func() bool {
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
		}, 5*time.Minute, 1*time.Second, "otel collector never got healthy")
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
			if latest != nil {
				return false
			}
			return true
		}, 5*time.Minute, 1*time.Second, "otel collector never stopped")
		latestErr := getLatestErr()
		require.NoError(t, latestErr, "runtime errored")
	}

	// ensure that it got healthy
	cfg, cfgErr := confmap.NewRetrieved(testConfig)
	require.NoError(t, cfgErr)
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
