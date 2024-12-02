// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package otel

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/provider/envprovider"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpprovider"
	"go.opentelemetry.io/collector/confmap/provider/httpsprovider"
	"go.opentelemetry.io/collector/confmap/provider/yamlprovider"

	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

func Run(ctx context.Context, stop chan bool, configFiles []string) error {
	fmt.Fprintln(os.Stdout, "Starting in otel mode")
	settings, err := newSettings(release.Version(), configFiles)
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
