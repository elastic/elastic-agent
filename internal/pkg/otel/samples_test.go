// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/featuregate"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSamples(t *testing.T) {
	// Set environment variables required by the sample configurations.
	// These are just sample values to allow the collector to start.
	t.Setenv("STORAGE_DIR", t.TempDir())
	t.Setenv("ELASTIC_ENDPOINT", "http://localhost:9200")
	t.Setenv("ELASTIC_API_KEY", "test_api_key")
	t.Setenv("ELASTIC_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("AUTOOPS_ES_URL", "http://localhost:9200")
	t.Setenv("AUTOOPS_TOKEN", "token")
	t.Setenv("AUTOOPS_TEMP_RESOURCE_ID", "temp")
	t.Setenv("AUTOOPS_OTEL_URL", "http://localhost:4318")

	// Enable service.profilesSupport featuregate to test the profiling samples.
	assert.NoError(t, featuregate.GlobalRegistry().Set("service.profilesSupport", true))
	defer func() {
		assert.NoError(t, featuregate.GlobalRegistry().Set("service.profilesSupport", false))
	}()

	err := filepath.WalkDir(filepath.Join(".", "samples", runtime.GOOS), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(d.Name()) == ".yaml" || filepath.Ext(d.Name()) == ".yml") {
			t.Run(d.Name(), func(t *testing.T) {
				testSample(t, filepath.Join(".", "samples", runtime.GOOS, d.Name()))
			})
		}
		return nil
	})
	assert.NoError(t, err)
}

func testSample(t *testing.T, configFile string) {
	settings := NewSettings("test", []string{configFile})
	settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
		// TODO: Replace with observer core. Right now, it results in a race condition.
		return zapcore.NewNopCore()
	})}
	collector, err := otelcol.NewCollector(*settings)
	assert.NoError(t, err)
	assert.NotNil(t, collector)
	assert.NoError(t, collector.DryRun(t.Context()))
	collector.Shutdown()
}
