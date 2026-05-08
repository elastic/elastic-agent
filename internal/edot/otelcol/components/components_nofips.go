// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package components

import (
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	kafkaexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter"
	kafkareceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkareceiver"
	prometheusreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"

	hbreceiver "github.com/elastic/beats/v7/x-pack/heartbeat/hbreceiver"
	osqreceiver "github.com/elastic/beats/v7/x-pack/osquerybeat/osqreceiver"
	pbreceiver "github.com/elastic/beats/v7/x-pack/packetbeat/pbreceiver"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

func addNonFipsReceivers(receivers []receiver.Factory) []receiver.Factory {
	receivers = append(receivers,
		kafkareceiver.NewFactory(),
		prometheusreceiver.NewFactory(),
		hbreceiver.NewFactoryWithSettings(hbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
		osqreceiver.NewFactoryWithSettings(osqreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
		pbreceiver.NewFactoryWithSettings(pbreceiver.Settings{Home: paths.Components(), Data: paths.Data()}),
	)

	return receivers
}

func addNonFipsExporters(exporters []exporter.Factory) []exporter.Factory {
	exporters = append(exporters,
		kafkaexporter.NewFactory(),
	)
	return exporters
}
