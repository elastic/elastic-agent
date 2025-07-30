// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package otel

import (
	kafkaexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter"

	apachereceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/apachereceiver"
	iisreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/iisreceiver"
	kafkareceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkareceiver"
	mysqlreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver"
	postgresqlreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"
	prometheusreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	sqlqueryreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlqueryreceiver"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

func addNonFipsReceivers(receivers []receiver.Factory) []receiver.Factory {
	receivers = append(receivers,
		apachereceiver.NewFactory(),
		iisreceiver.NewFactory(),
		kafkareceiver.NewFactory(),
		mysqlreceiver.NewFactory(),
		prometheusreceiver.NewFactory(),
		postgresqlreceiver.NewFactory(),
		sqlqueryreceiver.NewFactory(),
	)

	return receivers
}

func addNonFipsExporters(exporters []exporter.Factory) []exporter.Factory {
	exporters = append(exporters,
		kafkaexporter.NewFactory(),
	)
	return exporters
}
