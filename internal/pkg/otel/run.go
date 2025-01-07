// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/otel/configprovider"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

func Run(ctx context.Context, stop chan bool, configFiles []string) error {
	fmt.Fprintln(os.Stdout, "Starting in otel mode")
	settings := NewSettings(release.Version(), configFiles)
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

type options struct {
	resolverConfigProviders    []confmap.ProviderFactory
	resolverConverterFactories []confmap.ConverterFactory
	extensionFactories         []extension.Factory
}

type SettingOpt func(o *options)

func WithConfigProviderFactory(provider confmap.ProviderFactory) SettingOpt {
	return func(o *options) {
		o.resolverConfigProviders = append(o.resolverConfigProviders, provider)
	}
}

func WithConfigConvertorFactory(converter confmap.ConverterFactory) SettingOpt {
	return func(o *options) {
		o.resolverConverterFactories = append(o.resolverConverterFactories, converter)
	}
}

func WithExtensionFactory(factory extension.Factory) SettingOpt {
	return func(o *options) {
		o.extensionFactories = append(o.extensionFactories, factory)
	}
}

func NewSettings(version string, configPaths []string, opts ...SettingOpt) *otelcol.CollectorSettings {
	buildInfo := component.BuildInfo{
		Command:     os.Args[0],
		Description: buildDescription,
		Version:     version,
	}

	var o options
	for _, opt := range opts {
		opt(&o)
	}

	providerFactories := []confmap.ProviderFactory{
		configprovider.NewFactory(fileprovider.NewFactory),
		configprovider.NewFactory(envprovider.NewFactory),
		configprovider.NewFactory(yamlprovider.NewFactory),
		configprovider.NewFactory(httpprovider.NewFactory),
		configprovider.NewFactory(httpsprovider.NewFactory),
	}

	providerFactories = append(providerFactories, o.resolverConfigProviders...)
	var converterFactories []confmap.ConverterFactory
	converterFactories = append(converterFactories, o.resolverConverterFactories...)
	configProviderSettings := otelcol.ConfigProviderSettings{
		ResolverSettings: confmap.ResolverSettings{
			URIs:               configPaths,
			ProviderFactories:  providerFactories,
			DefaultScheme:      "env",
			ConverterFactories: converterFactories,
		},
	}

	return &otelcol.CollectorSettings{
		Factories:              components(o.extensionFactories...),
		BuildInfo:              buildInfo,
		ConfigProviderSettings: configProviderSettings,
		// we're handling DisableGracefulShutdown via the cancelCtx being passed
		// to the collector's Run method in the Run function
		DisableGracefulShutdown: true,
	}
}
