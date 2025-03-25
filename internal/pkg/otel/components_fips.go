// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package otel

import (
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

func addExtraReceivers(receivers []receiver.Factory) []receiver.Factory {
	return receivers
}

func addExtraExporters(exporters []exporter.Factory) []exporter.Factory {
	return exporters
}
