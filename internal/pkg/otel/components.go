// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"

	// Receivers:
	filelogreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver" // for collecting log files
	hostmetricsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	httpcheckreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver"
	jaegerreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jaegerreceiver"
	k8sclusterreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver"
	k8sobjectsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver"
	kubeletstatsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver"
	prometheusreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	zipkinreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/zipkinreceiver"
	otlpreceiver "go.opentelemetry.io/collector/receiver/otlpreceiver"

	fbreceiver "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	mbreceiver "github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"

	// Processors:
	attributesprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor" // for modifying signal attributes
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	k8sattributesprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor" // for adding k8s metadata
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor"
	resourceprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor"   // for modifying resource attributes
	transformprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor" // for OTTL processing on logs
	"go.opentelemetry.io/collector/processor/batchprocessor"                                                    // for batching events
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"

	"github.com/elastic/opentelemetry-collector-components/processor/elastictraceprocessor"
	"github.com/elastic/opentelemetry-collector-components/processor/lsmintervalprocessor"

	"github.com/elastic/opentelemetry-collector-components/processor/elasticinframetricsprocessor"

	// Exporters:
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	fileexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter" // for e2e tests
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/loadbalancingexporter"
	debugexporter "go.opentelemetry.io/collector/exporter/debugexporter" // for dev
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	otlphttpexporter "go.opentelemetry.io/collector/exporter/otlphttpexporter"

	// Extensions
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension"
	pprofextension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension"
	filestorage "github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"go.opentelemetry.io/collector/extension/memorylimiterextension" // for putting backpressure when approach a memory limit

	// Connectors
	routingconnector "github.com/open-telemetry/opentelemetry-collector-contrib/connector/routingconnector"
	spanmetricsconnector "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector"

	"github.com/elastic/opentelemetry-collector-components/connector/signaltometricsconnector"
)

func components(extensionFactories ...extension.Factory) func() (otelcol.Factories, error) {
	return func() (otelcol.Factories, error) {
		var err error
		factories := otelcol.Factories{}

		// Receivers
		factories.Receivers, err = receiver.MakeFactoryMap(
			otlpreceiver.NewFactory(),
			filelogreceiver.NewFactory(),
			kubeletstatsreceiver.NewFactory(),
			k8sclusterreceiver.NewFactory(),
			hostmetricsreceiver.NewFactory(),
			httpcheckreceiver.NewFactory(),
			k8sobjectsreceiver.NewFactory(),
			prometheusreceiver.NewFactory(),
			jaegerreceiver.NewFactory(),
			zipkinreceiver.NewFactory(),
			fbreceiver.NewFactory(),
			mbreceiver.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Processors
		factories.Processors, err = processor.MakeFactoryMap(
			batchprocessor.NewFactory(),
			resourceprocessor.NewFactory(),
			attributesprocessor.NewFactory(),
			transformprocessor.NewFactory(),
			filterprocessor.NewFactory(),
			k8sattributesprocessor.NewFactory(),
			elasticinframetricsprocessor.NewFactory(),
			resourcedetectionprocessor.NewFactory(),
			memorylimiterprocessor.NewFactory(),
			lsmintervalprocessor.NewFactory(),
			elastictraceprocessor.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Exporters
		factories.Exporters, err = exporter.MakeFactoryMap(
			otlpexporter.NewFactory(),
			debugexporter.NewFactory(),
			fileexporter.NewFactory(),
			elasticsearchexporter.NewFactory(),
			loadbalancingexporter.NewFactory(),
			otlphttpexporter.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		factories.Connectors, err = connector.MakeFactoryMap(
			routingconnector.NewFactory(),
			spanmetricsconnector.NewFactory(),
			signaltometricsconnector.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		extensions := []extension.Factory{
			memorylimiterextension.NewFactory(),
			filestorage.NewFactory(),
			healthcheckextension.NewFactory(),
			pprofextension.NewFactory(),
		}
		extensions = append(extensions, extensionFactories...)
		factories.Extensions, err = extension.MakeFactoryMap(extensions...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		return factories, err
	}
}
