// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otelcol

import (
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"

	// Receivers:
	apachereceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/apachereceiver"
	awss3receiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awss3receiver"
	dockerstatsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/dockerstatsreceiver"
	filelogreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver" // for collecting log files
	hostmetricsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	httpcheckreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver"
	iisreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/iisreceiver"
	jaegerreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jaegerreceiver"
	jmxreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jmxreceiver"
	k8sclusterreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver"
	k8seventsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8seventsreceiver"
	k8sobjectsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver"
	kafkametricsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkametricsreceiver"
	kubeletstatsreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver"
	mysqlreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver"
	nginxreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/nginxreceiver"
	postgresqlreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver"
	prometheusremotewritereceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusremotewritereceiver"
	receivercreator "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/receivercreator"
	redisreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/redisreceiver"
	snmpreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/snmpreceiver"
	sqlserverreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver"
	statsdreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/statsdreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/windowseventlogreceiver"
	windowsperfcountersreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/windowsperfcountersreceiver"
	zipkinreceiver "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/zipkinreceiver"
	nopreceiver "go.opentelemetry.io/collector/receiver/nopreceiver"
	otlpreceiver "go.opentelemetry.io/collector/receiver/otlpreceiver"

	elasticapmintakereceiver "github.com/elastic/opentelemetry-collector-components/receiver/elasticapmintakereceiver" // for collecting APM data from Elastic APM agents

	fbreceiver "github.com/elastic/beats/v7/x-pack/filebeat/fbreceiver"
	mbreceiver "github.com/elastic/beats/v7/x-pack/metricbeat/mbreceiver"

	// Processors:
	attributesprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor" // for modifying signal attributes
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/cumulativetodeltaprocessor"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor"
	geoipprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/geoipprocessor"                 // for adding geographical metadata associated to an IP address
	k8sattributesprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor" // for adding k8s metadata
	logdedupprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/logdedupprocessor"           // for deduplicating log events
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor"
	resourceprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor"         // for modifying resource attributes
	tailsamplingprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor" // for tail-based sampling
	transformprocessor "github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor"       // for OTTL processing on logs
	"go.opentelemetry.io/collector/processor/batchprocessor"                                                          // for batching events
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"

	elasticapmprocessor "github.com/elastic/opentelemetry-collector-components/processor/elasticapmprocessor"
	elastictraceprocessor "github.com/elastic/opentelemetry-collector-components/processor/elastictraceprocessor"

	"github.com/elastic/opentelemetry-collector-components/processor/elasticinframetricsprocessor"

	// Exporters:
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	fileexporter "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter" // for e2e tests
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/loadbalancingexporter"
	debugexporter "go.opentelemetry.io/collector/exporter/debugexporter" // for dev
	nopexporter "go.opentelemetry.io/collector/exporter/nopexporter"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	otlphttpexporter "go.opentelemetry.io/collector/exporter/otlphttpexporter"

	"github.com/elastic/beats/v7/x-pack/otel/exporter/logstashexporter"
	"github.com/elastic/beats/v7/x-pack/otel/processor/beatprocessor"

	// Extensions
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/awslogsencodingextension"
	headersetterextension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/headerssetterextension"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension"
	healthcheckv2extension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/k8sleaderelector"
	k8sobserver "github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer/k8sobserver"
	opampextension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/opampextension"
	pprofextension "github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension"
	filestorage "github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"go.opentelemetry.io/collector/extension/memorylimiterextension" // for putting backpressure when approach a memory limit

	elasticdiagnostics "github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"

	"github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension"
	"github.com/elastic/opentelemetry-collector-components/extension/apmconfigextension"

	// Connectors
	routingconnector "github.com/open-telemetry/opentelemetry-collector-contrib/connector/routingconnector"
	spanmetricsconnector "github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector"
	forwardconnector "go.opentelemetry.io/collector/connector/forwardconnector"

	"github.com/elastic/beats/v7/x-pack/otel/extension/beatsauthextension"
	elasticapmconnector "github.com/elastic/opentelemetry-collector-components/connector/elasticapmconnector"
	profilingmetricsconnector "github.com/elastic/opentelemetry-collector-components/connector/profilingmetricsconnector"

	// Telemetry
	internaltelemetry "github.com/elastic/elastic-agent/internal/pkg/otel/internaltelemetry"
	elasticmonitoringreceiver "github.com/elastic/elastic-agent/internal/pkg/otel/receivers/elasticmonitoring"
)

func components(extensionFactories ...extension.Factory) func() (otelcol.Factories, error) {
	return func() (otelcol.Factories, error) {
		var err error
		factories := otelcol.Factories{
			Telemetry: otelconftelemetry.NewFactory(),
		}

		// Internal telemetry monitoring
		factories.Telemetry = internaltelemetry.NewFactory()

		// Receivers
		receivers := []receiver.Factory{
			dockerstatsreceiver.NewFactory(),
			elasticapmintakereceiver.NewFactory(),
			otlpreceiver.NewFactory(),
			filelogreceiver.NewFactory(),
			kubeletstatsreceiver.NewFactory(),
			k8sclusterreceiver.NewFactory(),
			k8seventsreceiver.NewFactory(),
			hostmetricsreceiver.NewFactory(),
			httpcheckreceiver.NewFactory(),
			k8sobjectsreceiver.NewFactory(),
			receivercreator.NewFactory(),
			redisreceiver.NewFactory(),
			nginxreceiver.NewFactory(),
			jaegerreceiver.NewFactory(),
			zipkinreceiver.NewFactory(),
			elasticmonitoringreceiver.NewFactory(),
			fbreceiver.NewFactory(),
			mbreceiver.NewFactory(),
			jmxreceiver.NewFactory(), // deprecated, will be removed in 9.4.0

			nopreceiver.NewFactory(),
			apachereceiver.NewFactory(),
			iisreceiver.NewFactory(),
			mysqlreceiver.NewFactory(),
			postgresqlreceiver.NewFactory(),
			snmpreceiver.NewFactory(),
			kafkametricsreceiver.NewFactory(),
			sqlserverreceiver.NewFactory(),
			statsdreceiver.NewFactory(),
			windowseventlogreceiver.NewFactory(),
			awss3receiver.NewFactory(),
			windowsperfcountersreceiver.NewFactory(),
			prometheusremotewritereceiver.NewFactory(),
		}

		// some receivers are only available on certain OS.
		receivers = addOsSpecificReceivers(receivers)

		// some receivers should only be available when
		// not in fips mode due to restrictions on crypto usage
		receivers = addNonFipsReceivers(receivers)
		factories.Receivers, err = otelcol.MakeFactoryMap(receivers...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Processors
		factories.Processors, err = otelcol.MakeFactoryMap[processor.Factory](
			batchprocessor.NewFactory(),
			resourceprocessor.NewFactory(),
			attributesprocessor.NewFactory(),
			cumulativetodeltaprocessor.NewFactory(),
			transformprocessor.NewFactory(),
			filterprocessor.NewFactory(),
			geoipprocessor.NewFactory(),
			k8sattributesprocessor.NewFactory(),
			elasticinframetricsprocessor.NewFactory(),
			resourcedetectionprocessor.NewFactory(),
			memorylimiterprocessor.NewFactory(),
			elasticapmprocessor.NewFactory(),
			elastictraceprocessor.NewFactory(), // deprecated, will be removed in future
			tailsamplingprocessor.NewFactory(),
			logdedupprocessor.NewFactory(),
			beatprocessor.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		// Exporters
		exporters := []exporter.Factory{
			otlpexporter.NewFactory(),
			debugexporter.NewFactory(),
			fileexporter.NewFactory(),
			elasticsearchexporter.NewFactory(),
			loadbalancingexporter.NewFactory(),
			otlphttpexporter.NewFactory(),
			nopexporter.NewFactory(),
			logstashexporter.NewFactory(),
		}
		// some exporters should only be available when
		// not in fips mode due to restrictions on crypto usage
		exporters = addNonFipsExporters(exporters)
		factories.Exporters, err = otelcol.MakeFactoryMap(exporters...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		factories.Connectors, err = otelcol.MakeFactoryMap[connector.Factory](
			routingconnector.NewFactory(),
			spanmetricsconnector.NewFactory(),
			elasticapmconnector.NewFactory(),
			profilingmetricsconnector.NewFactory(),
			forwardconnector.NewFactory(),
		)
		if err != nil {
			return otelcol.Factories{}, err
		}

		extensions := []extension.Factory{
			k8sleaderelector.NewFactory(),
			healthcheckv2extension.NewFactory(),
			memorylimiterextension.NewFactory(),
			filestorage.NewFactory(),
			healthcheckextension.NewFactory(),
			bearertokenauthextension.NewFactory(),
			pprofextension.NewFactory(),
			k8sobserver.NewFactory(),
			apikeyauthextension.NewFactory(),
			apmconfigextension.NewFactory(),
			headersetterextension.NewFactory(),
			beatsauthextension.NewFactory(),
			elasticdiagnostics.NewFactory(),
			awslogsencodingextension.NewFactory(),
			opampextension.NewFactory(),
		}
		extensions = append(extensions, extensionFactories...)
		factories.Extensions, err = otelcol.MakeFactoryMap[extension.Factory](extensions...)
		if err != nil {
			return otelcol.Factories{}, err
		}

		return factories, err
	}
}
