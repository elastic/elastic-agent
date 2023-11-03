// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package factories

import (
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/debugexporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
)

var defaultExporters = []exporter.Factory{
	debugexporter.NewFactory(),
	exportertest.NewNopFactory(),
	fileexporter.NewFactory(),
	otlpexporter.NewFactory(),
	otlphttpexporter.NewFactory(),
}
