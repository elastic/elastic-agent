---
navigation_title: Custom Collector
description: How to build a custom OpenTelemetry Collector distribution similar to EDOT.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector: ga
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Build a Custom EDOT-like Collector

You can build and configure a [custom Collector](https://opentelemetry.io/docs/collector/custom-collector/) or extend the [OpenTelemetry Collector Contrib ](https://github.com/open-telemetry/opentelemetry-collector-contrib) distribution to collect logs and metrics and send them to Elastic Observability.

For a more seamless experience, use the Elastic Distribution of the OpenTelemetry Collector. Refer to the [configuration](/reference/edot-collector/config/index.md) docs for more information on configuring the EDOT Collector.

## Build a custom Collector

To build a custom Collector to collect your telemetry data and send it to Elastic Observability, you need to:

1. Install the OpenTelemetry Collector builder, `ocb`.
1. Create a builder configuration file.
1. Build the Collector.

Refer to the following sections to complete these steps.

### Install the OpenTelemetry Collector builder

Install `ocb` using the command that aligns with your system from the [OpenTelemetry building a custom Collector documentation](https://opentelemetry.io/docs/collector/custom-collector/#step-1---install-the-builder).

:::{important}
Make sure to install the version of OpenTelemetry Collector Builder that matches the desired components' version.
:::

### Create a builder configuration file

Create a builder configuration file,`builder-config.yml`, to define the custom Collector. This file specifies the components, such as extensions, exporters, processors, receivers, and connectors, included in your custom Collector.

The following example, `builder-config.yml`, contains the components needed to send your telemetry data to Elastic Observability. For more information on these components, refer to the [components](/reference/edot-collector/components.md) documentation. Keep or remove components from the example configuration file to fit your needs.

% The following OCB configuration is automatically generated from the EDOT Collector source code.
% Automation is handled by /docs/scripts/update-docs/update-components-docs.py, which
% reads the go.mod file and then generates the OCB configuration.
% Note that while this runs on `main`, the OCB configuration is updated based on the latest released version.

% start:edot-collector-components-ocb
This OCB configuration is for EDOT Collector version 9.2.0.

```yaml
dist:
  otelcol_edot:
    description: "Elastic Distribution of OpenTelemetry Collector"
    output_path: ./dist/otelcol_edot
    builds:
      - name: otelcol_edot
        goos: [linux, darwin, windows]
        goarch: [amd64, arm64]
        output_path: ./dist/otelcol_edot_{{ .OS }}_{{ .Arch }}
        env:
          - CGO_ENABLED=0
          - GOOS={{ .OS }}
          - GOARCH={{ .Arch }}
        ldflags:
          - -s -w
          - -X go.opentelemetry.io/collector/otelcol.buildTimestamp={{ .BuildTimestamp }}
          - -X go.opentelemetry.io/collector/otelcol.version={{ .Version }}

receivers:
  apachereceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/apachereceiver v0.137.0
  dockerstatsreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/dockerstatsreceiver v0.137.0
  elasticapmintakereceiver :
    gomod: github.com/elastic/opentelemetry-collector-components/receiver/elasticapmintakereceiver v0.4.0
  filelogreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v0.137.0
  hostmetricsreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver v0.137.0
  httpcheckreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver v0.137.0
  iisreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/iisreceiver v0.137.0
  jaegerreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jaegerreceiver v0.137.0
  jmxreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jmxreceiver v0.137.0
  k8sclusterreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver v0.137.0
  k8seventsreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8seventsreceiver v0.137.0
  k8sobjectsreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.137.0
  kafkareceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkareceiver v0.137.0
  kubeletstatsreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver v0.137.0
  mysqlreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver v0.137.0
  nginxreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/nginxreceiver v0.137.0
  nopreceiver :
    gomod: go.opentelemetry.io/collector/receiver/nopreceiver v0.137.0
  otlpreceiver :
    gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.137.0
  postgresqlreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver v0.137.0
  prometheusreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.137.0
  receivercreator :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/receivercreator v0.137.0
  redisreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/redisreceiver v0.137.0
  sqlserverreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver v0.137.0
  windowseventlogreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/windowseventlogreceiver v0.137.0
  zipkinreceiver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/zipkinreceiver v0.137.0

processors:
  attributesprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor v0.137.0
  batchprocessor :
    gomod: go.opentelemetry.io/collector/processor/batchprocessor v0.137.0
  cumulativetodeltaprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/cumulativetodeltaprocessor v0.137.0
  elasticapmprocessor :
    gomod: github.com/elastic/opentelemetry-collector-components/processor/elasticapmprocessor v0.4.0
  elasticinframetricsprocessor :
    gomod: github.com/elastic/opentelemetry-collector-components/processor/elasticinframetricsprocessor v0.18.0
  elastictraceprocessor :
    gomod: github.com/elastic/opentelemetry-collector-components/processor/elastictraceprocessor v0.13.0
  filterprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor v0.137.0
  geoipprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/geoipprocessor v0.137.0
  k8sattributesprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor v0.137.0
  memorylimiterprocessor :
    gomod: go.opentelemetry.io/collector/processor/memorylimiterprocessor v0.137.0
  resourcedetectionprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor v0.137.0
  resourceprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor v0.137.0
  tailsamplingprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor v0.137.0
  transformprocessor :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v0.137.0

exporters:
  debugexporter :
    gomod: go.opentelemetry.io/collector/exporter/debugexporter v0.137.0
  elasticsearchexporter :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter v0.137.0
  fileexporter :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter v0.137.0
  kafkaexporter :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter v0.137.0
  loadbalancingexporter :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/loadbalancingexporter v0.137.0
  nopexporter :
    gomod: go.opentelemetry.io/collector/exporter/nopexporter v0.137.0
  otlpexporter :
    gomod: go.opentelemetry.io/collector/exporter/otlpexporter v0.137.0
  otlphttpexporter :
    gomod: go.opentelemetry.io/collector/exporter/otlphttpexporter v0.137.0

connectors:
  elasticapmconnector :
    gomod: github.com/elastic/opentelemetry-collector-components/connector/elasticapmconnector v0.8.0
  forwardconnector :
    gomod: go.opentelemetry.io/collector/connector/forwardconnector v0.137.0
  profilingmetricsconnector :
    gomod: github.com/elastic/opentelemetry-collector-components/connector/profilingmetricsconnector v0.1.0
  routingconnector :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/connector/routingconnector v0.137.0
  spanmetricsconnector :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector v0.137.0

extensions:
  apikeyauthextension :
    gomod: github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension v0.8.0
  apmconfigextension :
    gomod: github.com/elastic/opentelemetry-collector-components/extension/apmconfigextension v0.8.0
  bearertokenauthextension :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension v0.137.0
  beatsauthextension :
    gomod: github.com/elastic/opentelemetry-collector-components/extension/beatsauthextension v0.5.0
  extensiontest :
    gomod: go.opentelemetry.io/collector/extension/extensiontest v0.137.0
  filestorage :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage v0.137.0
  headerssetterextension :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/headerssetterextension v0.137.0
  healthcheckextension :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension v0.137.0
  healthcheckv2extension :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension v0.137.0
  k8sleaderelector :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/k8sleaderelector v0.137.0
  k8sobserver :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer/k8sobserver v0.137.0
  memorylimiterextension :
    gomod: go.opentelemetry.io/collector/extension/memorylimiterextension v0.137.0
  pprofextension :
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension v0.137.0

providers:
  envprovider :
    gomod: go.opentelemetry.io/collector/confmap/provider/envprovider v1.43.0
  fileprovider :
    gomod: go.opentelemetry.io/collector/confmap/provider/fileprovider v1.43.0
  httpprovider :
    gomod: go.opentelemetry.io/collector/confmap/provider/httpprovider v1.43.0
  httpsprovider :
    gomod: go.opentelemetry.io/collector/confmap/provider/httpsprovider v1.35.0
  yamlprovider :
    gomod: go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.43.0
```
% end:edot-collector-components-ocb

### Build the Collector

Build your custom Collector using the `ocb` tool and the configuration file by running the following command: `builder --config builder-config.yml`.

The command generates a new Collector in the specified output path, `otelcol-dev`. The generated Collector includes the components you specified in the configuration file.

For general information on building a custom Collector, refer to the [OpenTelemetry documentation](https://opentelemetry.io/docs/collector/custom-collector/#step-1---install-the-builder).

