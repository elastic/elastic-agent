// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/converter/expandconverter"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

// IsOtelConfig returns true if file is named:
//   - otel.(yaml|yml)
//   - otlp.(yaml|yml)
//   - otelcol.(yaml|yml)
//
// In other cases it returns false assuming agent config for backwards compatibility
func IsOtelConfig(ctx context.Context, pathConfigFile string) bool {
	fileName := filepath.Base(pathConfigFile)
	if suffix := filepath.Ext(fileName); suffix != ".yml" && suffix != ".yaml" {
		return false
	}

	cleanFileName := strings.TrimSpace(strings.ToLower(strings.TrimSuffix(fileName, filepath.Ext(fileName))))
	if cleanFileName == "otel" || cleanFileName == "otlp" || cleanFileName == "otelcol" {
		return true
	}

	// default behavior is Elastic Agent
	return false
}

func Run(ctx context.Context, cancel context.CancelFunc, stop chan bool, testingMode bool) error {
	fmt.Fprintln(os.Stdout, "Starting in otel mode")
	settings, err := newSettings(paths.ConfigFile(), release.Version())
	if err != nil {
		return err
	}

	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		return err
	}

	// cancel context on stop from event manager
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		<-stop
		cancel()
	}()
	defer cancel()

	return svc.Run(cancelCtx)
}

func newSettings(configPath string, version string) (*otelcol.CollectorSettings, error) {
	buildInfo := component.BuildInfo{
		Command:     os.Args[0],
		Description: buildDescription,
		Version:     version,
	}

	fmp := NewFileProviderWithDefaults()
	configProviderSettings := otelcol.ConfigProviderSettings{
		ResolverSettings: confmap.ResolverSettings{
			URIs:       []string{configPath},
			Providers:  map[string]confmap.Provider{fmp.Scheme(): fmp},
			Converters: []confmap.Converter{expandconverter.New()},
		},
	}
	provider, err := otelcol.NewConfigProvider(configProviderSettings)
	if err != nil {
		return nil, err
	}

	return &otelcol.CollectorSettings{
		Factories:      components,
		BuildInfo:      buildInfo,
		ConfigProvider: provider,
		// we're handling DisableGracefulShutdown via the cancelCtx being passed
		// to the collector's Run method in the Run function
		DisableGracefulShutdown: true,
	}, nil
}
