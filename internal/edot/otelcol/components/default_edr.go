// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build edr

package components

import (
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	// Receivers:
	nopreceiver "go.opentelemetry.io/collector/receiver/nopreceiver"

	fbreceiver "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	mbreceiver "github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"

	// Processors:
	"github.com/elastic/beats/v7/x-pack/otel/processor/beatprocessor"

	// Exporters:
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	fileexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter"
	kafkaexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter"

	"github.com/elastic/beats/v7/x-pack/otel/exporter/logstashexporter"

	// Extensions:
	healthcheckv2extension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension"

	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension"
	kafkapartitionerextension "github.com/elastic/beats/v7/x-pack/otel/extension/kafkapartitionerextension"
	elasticdiagnostics "github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"

	// Connectors:
	forwardconnector "go.opentelemetry.io/collector/connector/forwardconnector"

	elasticmonitoringconnector "github.com/elastic/elastic-agent/internal/edot/connectors/elasticmonitoring"

	// Telemetry:
	internaltelemetry "github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
	elasticmonitoringreceiver "github.com/elastic/elastic-agent/internal/edot/receivers/elasticmonitoring"
)

// Default returns the factory function for the EDR flavor EDOT collector
// component set — a minimal registry containing only the components required
// for the EDR flavor and agent self-monitoring. Pass extra extension
// factories to register them alongside the defaults.
func Default(extensionFactories ...extension.Factory) func() (otelcol.Factories, error) {
	return func() (otelcol.Factories, error) {
		var err error
		factories := otelcol.Factories{
			Telemetry: otelconftelemetry.NewFactory(),
		}

		// Internal telemetry monitoring
		factories.Telemetry = internaltelemetry.NewFactory()

		// Receivers
		receivers := []receiver.Factory{
			elasticmonitoringreceiver.NewFactory(),
			fbreceiver.NewFactoryWithSettings(fbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
			mbreceiver.NewFactoryWithSettings(mbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
			nopreceiver.NewFactory(),
		}

		// osquerybeat receiver is added here; packetbeat, kafka, and prometheus
		// receivers are excluded from the EDR flavor build
		receivers = addNonFipsReceivers(receivers)

		// auditbeat receiver is added here; the heartbeat receiver is excluded
		// from the EDR flavor build
		receivers = addFullBeatReceivers(receivers)

		factories.Receivers, err = otelcol.MakeFactoryMap(receivers...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Processors — only the beat processor used by beats receiver pipelines
		factories.Processors, err = otelcol.MakeFactoryMap[processor.Factory](
			beatprocessor.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Exporters
		exporters := []exporter.Factory{
			elasticsearchexporter.NewFactory(),
			fileexporter.NewFactory(),
			kafkaexporter.NewFactory(),
			logstashexporter.NewFactory(),
		}
		exporters = addNonFipsExporters(exporters)
		factories.Exporters, err = otelcol.MakeFactoryMap(exporters...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		factories.Connectors, err = otelcol.MakeFactoryMap[connector.Factory](
			forwardconnector.NewFactory(),
			elasticmonitoringconnector.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		extensions := []extension.Factory{
			healthcheckv2extension.NewFactory(),
			beatsauthextension.NewFactory(),
			elasticdiagnostics.NewFactory(),
			kafkapartitionerextension.NewFactory(),
		}
		extensions = append(extensions, extensionFactories...)
		factories.Extensions, err = otelcol.MakeFactoryMap[extension.Factory](extensions...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		return factories, err
	}
}
