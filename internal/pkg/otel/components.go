// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package otel

import (
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"

	// Receivers:
	filelogreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver" // for collecting log files
	hostmetricsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	k8sclusterreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver"
	kubeletstatsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver"
	otlpreceiver "go.opentelemetry.io/collector/receiver/otlpreceiver"

	// Processors:
	attributesprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor" // for modifying signal attributes
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	resourceprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor"   // for modifying resource attributes
	transformprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor" // for OTTL processing on logs
	"go.opentelemetry.io/collector/processor/batchprocessor"                                                    // for batching events
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"                                            // for putting backpressure when approach a memory limit

	// Exporters:
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	fileexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter" // for e2e tests
	debugexporter "go.opentelemetry.io/collector/exporter/debugexporter"                           // for dev
	"go.opentelemetry.io/collector/exporter/otlpexporter"
<<<<<<< HEAD
=======

	// Extensions
	filestorage "github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"go.opentelemetry.io/collector/extension/memorylimiterextension" // for putting backpressure when approach a memory limit
>>>>>>> 6b7879127d (Added k8s components to otel distribution (#4908))
)

func components() (otelcol.Factories, error) {
	var err error
	factories := otelcol.Factories{}

	// Receivers
	factories.Receivers, err = receiver.MakeFactoryMap(
		otlpreceiver.NewFactory(),
		filelogreceiver.NewFactory(),
		kubeletstatsreceiver.NewFactory(),
		k8sclusterreceiver.NewFactory(),
		hostmetricsreceiver.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

	// Processors
	factories.Processors, err = processor.MakeFactoryMap(
		batchprocessor.NewFactory(),
		memorylimiterprocessor.NewFactory(),
		resourceprocessor.NewFactory(),
		attributesprocessor.NewFactory(),
		transformprocessor.NewFactory(),
		filterprocessor.NewFactory(),
<<<<<<< HEAD
=======
		k8sattributesprocessor.NewFactory(),
		resourcedetectionprocessor.NewFactory(),
>>>>>>> 6b7879127d (Added k8s components to otel distribution (#4908))
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
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

<<<<<<< HEAD
=======
	factories.Extensions, err = extension.MakeFactoryMap(
		memorylimiterextension.NewFactory(),
		filestorage.NewFactory(),
	)
	if err != nil {
		return otelcol.Factories{}, err
	}

>>>>>>> 6b7879127d (Added k8s components to otel distribution (#4908))
	return factories, err
}
