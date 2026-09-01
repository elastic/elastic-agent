// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build securityonly

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
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"

	"github.com/elastic/beats/v7/x-pack/otel/processor/beatprocessor"

	// Exporters:
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	debugexporter "go.opentelemetry.io/collector/exporter/debugexporter"
	nopexporter "go.opentelemetry.io/collector/exporter/nopexporter"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	otlphttpexporter "go.opentelemetry.io/collector/exporter/otlphttpexporter"

	"github.com/elastic/beats/v7/x-pack/otel/exporter/logstashexporter"

	// Extensions:
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/cgroupruntimeextension"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension"
	healthcheckv2extension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension"
	pprofextension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension"
	filestorage "github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"go.opentelemetry.io/collector/extension/memorylimiterextension"

	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension"
	elasticdiagnostics "github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"

	// Connectors:
	forwardconnector "go.opentelemetry.io/collector/connector/forwardconnector"

	elasticmonitoringconnector "github.com/elastic/elastic-agent/internal/edot/connectors/elasticmonitoring"

	// Telemetry:
	internaltelemetry "github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
	elasticmonitoringreceiver "github.com/elastic/elastic-agent/internal/edot/receivers/elasticmonitoring"
	verifierreceiver "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"
)

// Default returns the factory function for the security-only variant EDOT collector
// component set — a minimal registry containing only the components required
// for endpoint security and agent self-monitoring. Pass extra extension
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
			verifierreceiver.NewFactory(),
			fbreceiver.NewFactoryWithSettings(fbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
			mbreceiver.NewFactoryWithSettings(mbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
			nopreceiver.NewFactory(),
		}

		// osquerybeat receiver is added here; packetbeat, kafka, and prometheus
		// receivers are excluded from the security-only variant build
		receivers = addNonFipsReceivers(receivers)

		// auditbeat and heartbeat receivers are intentionally excluded; the
		// addFullBeatReceivers hook is a no-op for the security-only variant
		receivers = addFullBeatReceivers(receivers)

		factories.Receivers, err = otelcol.MakeFactoryMap(receivers...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Processors — only the components required for beats receiver pipelines
		// and basic collector safety; all policy-facing processors are excluded
		factories.Processors, err = otelcol.MakeFactoryMap[processor.Factory](
			batchprocessor.NewFactory(),
			memorylimiterprocessor.NewFactory(),
			beatprocessor.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Exporters
		exporters := []exporter.Factory{
			otlpexporter.NewFactory(),
			debugexporter.NewFactory(),
			elasticsearchexporter.NewFactory(),
			otlphttpexporter.NewFactory(),
			nopexporter.NewFactory(),
			logstashexporter.NewFactory(),
		}
		// kafka exporter is excluded from the security-only variant build
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
			cgroupruntimeextension.NewFactory(),
			healthcheckv2extension.NewFactory(),
			memorylimiterextension.NewFactory(),
			filestorage.NewFactory(),
			healthcheckextension.NewFactory(),
			pprofextension.NewFactory(),
			beatsauthextension.NewFactory(),
			elasticdiagnostics.NewFactory(),
		}
		extensions = append(extensions, extensionFactories...)
		factories.Extensions, err = otelcol.MakeFactoryMap[extension.Factory](extensions...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		return factories, err
	}
}
