// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package otel

import (
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

func addNonFipsReceivers(receivers []receiver.Factory) []receiver.Factory {
	// do not add non fips receivers in fips mode
	return receivers
}

func addNonFipsExporters(exporters []exporter.Factory) []exporter.Factory {
	// do not add non fips exporters in fips mode
	return exporters
}
