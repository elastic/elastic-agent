// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package main

import (
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/nopexporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/nopreceiver"

	healthcheckv2extension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension"

	internaltelemetry "github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
	elasticdiagnostics "github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
)

// testComponents returns the minimal set of OTel factories needed by the
// manager unit tests. Tests only use nop receivers/exporters, batch processor,
// healthcheckv2 extension (injected by the manager), and elasticdiagnostics
// extension (force-injected on every startup).
func testComponents() (otelcol.Factories, error) {
	var err error
	factories := otelcol.Factories{
		Telemetry: internaltelemetry.NewFactory(),
	}

	factories.Receivers, err = otelcol.MakeFactoryMap[receiver.Factory](
		nopreceiver.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	factories.Processors, err = otelcol.MakeFactoryMap[processor.Factory](
		batchprocessor.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	factories.Exporters, err = otelcol.MakeFactoryMap[exporter.Factory](
		nopexporter.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	factories.Extensions, err = otelcol.MakeFactoryMap[extension.Factory](
		healthcheckv2extension.NewFactory(),
		elasticdiagnostics.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	return factories, nil
}
