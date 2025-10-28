// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestSamples(t *testing.T) {
	// Set environment variables required by the sample configurations.
	// These are just sample values to allow the collector to start.
	os.Setenv("STORAGE_DIR", t.TempDir())
	os.Setenv("ELASTIC_ENDPOINT", "http://localhost:9200")
	os.Setenv("ELASTIC_API_KEY", "test_api_key")
	os.Setenv("ELASTIC_OTLP_ENDPOINT", "http://localhost:4318")
	os.Setenv("AUTOOPS_ES_URL", "http://localhost:9200")
	os.Setenv("AUTOOPS_TOKEN", "token")
	os.Setenv("AUTOOPS_TEMP_RESOURCE_ID", "temp")
	os.Setenv("AUTOOPS_OTEL_URL", "http://localhost:4318")

	defer func() {
		os.Unsetenv("STORAGE_DIR")
		os.Unsetenv("ELASTIC_ENDPOINT")
		os.Unsetenv("ELASTIC_API_KEY")
		os.Unsetenv("ELASTIC_OTLP_ENDPOINT")
		os.Unsetenv("AUTOOPS_ES_URL")
		os.Unsetenv("AUTOOPS_TOKEN")
		os.Unsetenv("AUTOOPS_TEMP_RESOURCE_ID")
		os.Unsetenv("AUTOOPS_OTEL_URL")
	}()
	err := filepath.WalkDir(filepath.Join(".", "samples", runtime.GOOS), func(path string, d os.DirEntry, err error) error {
		fmt.Println(path)
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
		return zapcore.NewNopCore()
	})}
	collector, err := otelcol.NewCollector(*settings)
	assert.NoError(t, err)
	assert.NotNil(t, collector)

	wg := startCollector(context.Background(), t, collector, "")

	assert.Eventually(t, func() bool {
		return otelcol.StateRunning == collector.GetState()
	}, 10*time.Second, 200*time.Millisecond)
	collector.Shutdown()
	wg.Wait()
	assert.Equal(t, otelcol.StateClosed, collector.GetState())
}
