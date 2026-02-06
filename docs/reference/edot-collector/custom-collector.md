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

# Build a custom EDOT-like collector

You can build and configure a [custom Collector](https://opentelemetry.io/docs/collector/custom-collector/) or extend the [OpenTelemetry Collector Contrib ](https://github.com/open-telemetry/opentelemetry-collector-contrib) distribution to collect logs and metrics and send them to Elastic Observability.

For a more seamless experience, use the Elastic Distribution of the OpenTelemetry Collector. Refer to the [configuration](/reference/edot-collector/config/index.md) docs for more information on configuring the EDOT Collector.

## Build a custom collector

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
This OCB configuration is for EDOT Collector version 9.3.0.

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
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/apachereceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/awss3receiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/dockerstatsreceiver v0.141.0
  - gomod: github.com/elastic/opentelemetry-collector-components/receiver/elasticapmintakereceiver v0.24.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/iisreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jaegerreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jmxreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8seventsreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kafkareceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/mysqlreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/nginxreceiver v0.141.0
  - gomod: go.opentelemetry.io/collector/receiver/nopreceiver v0.141.0
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/postgresqlreceiver v0.141.0
  - gomod: go.opentelemetry.io/ebpf-profiler v0.0.202547
    import: go.opentelemetry.io/ebpf-profiler/collector
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusremotewritereceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/receivercreator v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/redisreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/snmpreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/sqlserverreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/windowseventlogreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/windowsperfcountersreceiver v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/receiver/zipkinreceiver v0.141.0

processors:
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor v0.141.0
  - gomod: go.opentelemetry.io/collector/processor/batchprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/cumulativetodeltaprocessor v0.141.0
  - gomod: github.com/elastic/opentelemetry-collector-components/processor/elasticapmprocessor v0.24.0
  - gomod: github.com/elastic/opentelemetry-collector-components/processor/elasticinframetricsprocessor v0.24.0
  - gomod: github.com/elastic/opentelemetry-collector-components/processor/elastictraceprocessor v0.24.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/geoipprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor v0.141.0
  - gomod: go.opentelemetry.io/collector/processor/memorylimiterprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/tailsamplingprocessor v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v0.141.0

exporters:
  - gomod: go.opentelemetry.io/collector/exporter/debugexporter v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/kafkaexporter v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/loadbalancingexporter v0.141.0
  - gomod: go.opentelemetry.io/collector/exporter/nopexporter v0.141.0
  - gomod: go.opentelemetry.io/collector/exporter/otlpexporter v0.141.0
  - gomod: go.opentelemetry.io/collector/exporter/otlphttpexporter v0.141.0

connectors:
  - gomod: github.com/elastic/opentelemetry-collector-components/connector/elasticapmconnector v0.24.0
  - gomod: go.opentelemetry.io/collector/connector/forwardconnector v0.141.0
  - gomod: github.com/elastic/opentelemetry-collector-components/connector/profilingmetricsconnector v0.25.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/connector/routingconnector v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector v0.141.0

extensions:
  - gomod: github.com/elastic/opentelemetry-collector-components/extension/apikeyauthextension v0.24.0
  - gomod: github.com/elastic/opentelemetry-collector-components/extension/apmconfigextension v0.24.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/awslogsencodingextension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/bearertokenauthextension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/headerssetterextension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckv2extension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/k8sleaderelector v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/observer/k8sobserver v0.141.0
  - gomod: go.opentelemetry.io/collector/extension/memorylimiterextension v0.141.0
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension v0.141.0

providers:
  - gomod: go.opentelemetry.io/collector/confmap/provider/envprovider v1.47.0
  - gomod: go.opentelemetry.io/collector/confmap/provider/fileprovider v1.47.0
  - gomod: go.opentelemetry.io/collector/confmap/provider/httpprovider v1.47.0
  - gomod: go.opentelemetry.io/collector/confmap/provider/httpsprovider v1.47.0
  - gomod: go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.47.0
```
% end:edot-collector-components-ocb

### Build the Collector

Build your custom Collector using the `ocb` tool and the configuration file by running the following command: `builder --config builder-config.yml`.

The command generates a new Collector in the specified output path, `otelcol-dev`. The generated Collector includes the components you specified in the configuration file.

For general information on building a custom Collector, refer to the [OpenTelemetry documentation](https://opentelemetry.io/docs/collector/custom-collector/#step-1---install-the-builder).

