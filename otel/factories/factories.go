// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package factories

import (
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/multierr"
)

// DefaultFactories returns the default factories used by the Elastic Agent
func DefaultFactories() (otelcol.Factories, error) {
	return combineFactories(defaultReceivers, defaultProcessors, defaultExporters, defaultExtensions, defaultConnectors)
}

func combineFactories(receivers []receiver.Factory, processors []processor.Factory,
	exporters []exporter.Factory, extensions []extension.Factory,
	connectors []connector.Factory) (otelcol.Factories, error) {
	var errs []error

	receiverMap, err := receiver.MakeFactoryMap(receivers...)
	if err != nil {
		errs = append(errs, err)
	}

	processorMap, err := processor.MakeFactoryMap(processors...)
	if err != nil {
		errs = append(errs, err)
	}

	exporterMap, err := exporter.MakeFactoryMap(exporters...)
	if err != nil {
		errs = append(errs, err)
	}

	extensionMap, err := extension.MakeFactoryMap(extensions...)
	if err != nil {
		errs = append(errs, err)
	}

	connectorMap, err := connector.MakeFactoryMap(connectors...)
	if err != nil {
		errs = append(errs, err)
	}

	return otelcol.Factories{
		Receivers:  receiverMap,
		Processors: processorMap,
		Exporters:  exporterMap,
		Extensions: extensionMap,
		Connectors: connectorMap,
	}, multierr.Combine(errs...)
}
