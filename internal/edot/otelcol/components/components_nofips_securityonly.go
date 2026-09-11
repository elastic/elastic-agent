// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips && securityonly

package components

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	osqreceiver "github.com/elastic/beats/v7/x-pack/osquerybeat/osqreceiver"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

// addNonFipsReceivers adds the osquerybeat receiver for the security-only variant
// build. Kafka, Prometheus, and packetbeat receivers are intentionally excluded.
func addNonFipsReceivers(receivers []receiver.Factory) []receiver.Factory {
	return append(receivers,
		osqreceiver.NewFactoryWithSettings(osqreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
	)
}

// addNonFipsExporters is a no-op for the security-only variant: the kafka exporter
// is not included in the security-only variant build.
func addNonFipsExporters(exporters []exporter.Factory) []exporter.Factory {
	return exporters
}
