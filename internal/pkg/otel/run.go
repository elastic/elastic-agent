// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package otel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/converter/expandconverter"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpsprovider"
	"go.opentelemetry.io/collector/confmap/provider/yamlprovider"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

func Run(ctx context.Context, stop chan bool, configFiles []string) error {
	fmt.Fprintln(os.Stdout, "Starting in otel mode")
	settings, err := newSettings(release.Version(), configFiles)
	if err != nil {
		return err
	}

	if err := ensureRegistryExists(); err != nil {
		return fmt.Errorf("error while creating registry: %w", err)
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

func newSettings(version string, configPaths []string) (*otelcol.CollectorSettings, error) {
	buildInfo := component.BuildInfo{
		Command:     os.Args[0],
		Description: buildDescription,
		Version:     version,
	}
	configProviderSettings := otelcol.ConfigProviderSettings{
		ResolverSettings: confmap.ResolverSettings{
			URIs: configPaths,
			ProviderFactories: []confmap.ProviderFactory{
				fileprovider.NewFactory(),
				envprovider.NewFactory(),
				yamlprovider.NewFactory(),
				httpprovider.NewFactory(),
				httpsprovider.NewFactory(),
			},
			ConverterFactories: []confmap.ConverterFactory{
				expandconverter.NewFactory(),
			},
		},
	}

	return &otelcol.CollectorSettings{
		Factories:              components,
		BuildInfo:              buildInfo,
		ConfigProviderSettings: configProviderSettings,
		// we're handling DisableGracefulShutdown via the cancelCtx being passed
		// to the collector's Run method in the Run function
		DisableGracefulShutdown: true,
	}, nil
}

func ensureRegistryExists() error {
	storageDir := os.Getenv("STORAGE_DIR")
	if storageDir == "" {

		// by default use "${path.data}/registry/otelcol" to store offsets
		storageDir = filepath.Join(paths.Data(), "registry", "otelcol")

		// set the STORAGE_DIR env. This will be used by otel collectore to get the registry directory
		os.Setenv("STORAGE_DIR", storageDir)
	}
	if _, err := os.Stat(storageDir); err == nil {
		// directory exists
		return nil
	} else if os.IsNotExist(err) {
		return os.MkdirAll(storageDir, 0755)
	} else {
		return fmt.Errorf("error stating %s: %w", storageDir, err)
	}
}
