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
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
)

const buildDescription = "Elastic opentelemetry-collector distribution"

// IsOtelConfig returns true if file is named:
//   - otel.(yaml|yml)
//   - otlp.(yaml|yml)
//   - otelcol.(yaml|yml)
//
// in case of other filename it checks for `agent`, `inputs`, `outputs` keyword. If at least one of these is present
// it assumes agent config and returns (false, nil).
// If these keywords are missing it checks for presence of otel specific keywords `exporters`, `receivers`,`processors`
// or `extensions` in combination with `service` definition. In case these are found (true, nil) is returned.
// If none of these conditions are satisfied (false, nil) is returned assuming agent config for backward compatibility.
func IsOtelConfig(ctx context.Context, pathConfigFile string) (bool, error) {
	fileName := filepath.Base(pathConfigFile)
	cleanFileName := strings.TrimSpace(strings.ToLower(strings.TrimSuffix(fileName, filepath.Ext(fileName))))
	if cleanFileName == "otel" || cleanFileName == "otlp" || cleanFileName == "otelcol" {
		return true, nil
	}

	if suffix := filepath.Ext(fileName); suffix != ".yml" && suffix != ".yaml" {
		return false, nil
	}

	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return false, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	mapConfig, err := rawConfig.ToMapStr()
	if err != nil {
		return false, errors.New(err,
			errors.TypeConfig,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	// contains agent definition
	_, hasAgent := mapConfig["agent"]
	_, hasInputs := mapConfig["inputs"]
	_, hasOutputs := mapConfig["outputs"]

	if hasAgent || hasInputs || hasOutputs {
		return false, nil
	}

	// contains otel service definition
	_, hasService := mapConfig["service"]
	_, hasExporters := mapConfig["exporters"]
	_, hasReceivers := mapConfig["receivers"]
	_, hasProcessors := mapConfig["processors"]
	_, hasExtensions := mapConfig["extensions"]

	if hasService && (hasExporters || hasReceivers || hasProcessors || hasExtensions) {
		return true, nil
	}

	// default behavior is Elastic Agent
	return false, nil
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

func newSettings(configPaths string, version string) (*otelcol.CollectorSettings, error) {
	buildInfo := component.BuildInfo{
		Command:     os.Args[0],
		Description: buildDescription,
		Version:     version,
	}

	fmp := NewFileProviderWithDefaults()
	configProviderSettings := otelcol.ConfigProviderSettings{
		ResolverSettings: confmap.ResolverSettings{
			URIs:       []string{configPaths},
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
