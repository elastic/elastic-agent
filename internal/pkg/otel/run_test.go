// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/otelcol"
)

// getConfigFiles returns a collection of config file paths for the collector to use.
// In the simplest scenario, the collection will contains only one path.
// In case there is an operating system-specific override file found, it will be added to the collection.
// E.g. if the input file name is `all-components.yml` and a file named `all-components.windows.yml` exists,
// the config path collection will have two elements on Windows, and only one element on other OSes.
// Use `darwin` for MacOS, `linux` for Linux and `windows` for Windows.
func getConfigFiles(configFileName string) []string {
	// Add base file to the collection.
	baseFilePath := filepath.Join(".", "testdata", configFileName)
	configFiles := []string{"file:" + baseFilePath}

	// Check if an os-specific override file exists; if it does, add it to the collection.
	overrideFileName := strings.TrimSuffix(configFileName, filepath.Ext(configFileName)) + "." + runtime.GOOS + filepath.Ext(configFileName)
	overrideFilePath := filepath.Join(".", "testdata", overrideFileName)
	if _, err := os.Stat(overrideFilePath); err == nil {
		configFiles = append(configFiles, "file:"+overrideFilePath)
	}

	return configFiles
}

func startCollector(ctx context.Context, t *testing.T, col *otelcol.Collector, expectedErrorMessage string) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := col.Run(ctx)
		if expectedErrorMessage == "" {
			require.NoError(t, err)
		} else {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), expectedErrorMessage)
		}
	}()
	return wg
}
