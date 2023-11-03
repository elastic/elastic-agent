// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package collector

import (
	"os"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/converter/expandconverter"
	"go.opentelemetry.io/collector/confmap/provider/fileprovider"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

func NewSettings(configPaths []string, version string, loggingOpts []zap.Option, factories otelcol.Factories) (*otelcol.CollectorSettings, error) {
	buildInfo := component.BuildInfo{
		Command:     os.Args[0],
		Description: buildDescription,
		Version:     version,
	}

	fmp := fileprovider.New()
	configProviderSettings := otelcol.ConfigProviderSettings{
		ResolverSettings: confmap.ResolverSettings{
			URIs:       configPaths,
			Providers:  map[string]confmap.Provider{fmp.Scheme(): fmp},
			Converters: []confmap.Converter{expandconverter.New()},
		},
	}
	provider, err := otelcol.NewConfigProvider(configProviderSettings)
	if err != nil {
		return nil, err
	}

	return &otelcol.CollectorSettings{
		Factories:               factories,
		BuildInfo:               buildInfo,
		LoggingOptions:          loggingOpts,
		ConfigProvider:          provider,
		DisableGracefulShutdown: true,
	}, nil
}
