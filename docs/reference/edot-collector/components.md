---
navigation_title: Components
description: List of components included in the EDOT Collector, categorized as Core or Extended.
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

# Components included in the EDOT Collector

The {{edot}} (EDOT) Collector includes embedded Collector components from the [OTel Collector Core](https://github.com/open-telemetry/opentelemetry-collector),
[OTel Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-contrib) and the [Elastic Collector Components](https://github.com/elastic/opentelemetry-collector-components) repositories.

The components included in the EDOT Collector are categorized into **[Core]** and **[Extended]** components. The following table describes the current components included in the EDOT Collector, their source, and support status.

% The following table is automatically generated from the EDOT Collector source code.
% Automation is handled by /docs/scripts/update-docs/update-components-docs.py, which
% reads the go.mod file, the components.yml file, and then generates the table.
% Note that while this runs on `main`, the table is updated based on the latest released version.

% start:edot-collector-components-table
## List of components

These components are included in EDOT Collector version 9.2.1.

| Component | GitHub Repo | Support status | Version |
|:---|:---|:---|:---|
|***Receivers***||||
| [apachereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/apachereceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [dockerstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/dockerstatsreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [elasticapmintakereceiver](/reference/edot-collector/components/elasticapmintakereceiver.md) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Core] | v0.4.0 |
| [filelogreceiver](/reference/edot-collector/components/filelogreceiver.md) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [hostmetricsreceiver](/reference/edot-collector/components/hostmetricsreceiver.md) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [httpcheckreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/httpcheckreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [iisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/iisreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jaegerreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [jmxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jmxreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [k8sclusterreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [k8seventsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8seventsreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [k8sobjectsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [kafkareceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [kubeletstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [mysqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/mysqlreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/nginxreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [nopreceiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/nopreceiver) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [otlpreceiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v0.137.0 |
| [postgresqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/postgresqlreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [receivercreator](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/receivercreator) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [redisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [sqlserverreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/sqlserverreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [windowseventlogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/windowseventlogreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [zipkinreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/zipkinreceiver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
|***Exporters***||||
| [debugexporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/debugexporter) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [elasticsearchexporter](/reference/edot-collector/components/elasticsearchexporter.md) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [fileexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/fileexporter) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [kafkaexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/kafkaexporter) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [loadbalancingexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/loadbalancingexporter) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [nopexporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/nopexporter) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [otlpexporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/otlpexporter) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v0.137.0 |
| [otlphttpexporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/otlphttpexporter) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v0.137.0 |
|***Processors***||||
| [attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [batchprocessor](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/batchprocessor) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v0.137.0 |
| [cumulativetodeltaprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/cumulativetodeltaprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [elasticapmprocessor](/reference/edot-collector/components/elasticapmprocessor.md) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Core] | v0.4.0 |
| [elasticinframetricsprocessor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | Deprecated | v0.18.0 |
| [elastictraceprocessor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elastictraceprocessor) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | Deprecated | v0.13.0 |
| [filterprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [geoipprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/geoipprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [k8sattributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/k8sattributesprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [memorylimiterprocessor](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/memorylimiterprocessor) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [resourcedetectionprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [resourceprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [tailsamplingprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [transformprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/transformprocessor) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
|***Connectors***||||
| [elasticapmconnector](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Core] | v0.8.0 |
| [forwardconnector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [profilingmetricsconnector](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/profilingmetricsconnector) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Extended] | v0.1.0 |
| [routingconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/routingconnector) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [spanmetricsconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/spanmetricsconnector) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
|***Extensions***||||
| [apikeyauthextension](/reference/edot-collector/config/authentication-methods.md) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Extended] | v0.8.0 |
| [apmconfigextension](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Extended] | v0.8.0 |
| [bearertokenauthextension](/reference/edot-collector/config/authentication-methods.md) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [beatsauthextension](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/beatsauthextension) | [Elastic Repo](https://github.com/elastic/opentelemetry-collector-components) | [Extended] | v0.5.0 |
| [extensiontest](https://github.com/open-telemetry/opentelemetry-collector/tree/main/extension/extensiontest) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [filestorage](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/storage/filestorage) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Core] | v0.137.0 |
| [headerssetterextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/headerssetterextension) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [healthcheckextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckextension) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [healthcheckv2extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckv2extension) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [k8sleaderelector](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/k8sleaderelector) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [k8sobserver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/observer/k8sobserver) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
| [memorylimiterextension](https://github.com/open-telemetry/opentelemetry-collector/tree/main/extension/memorylimiterextension) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Extended] | v0.137.0 |
| [pprofextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/pprofextension) | [OTel Contrib Repo](https://github.com/open-telemetry/opentelemetry-collector-contrib) | [Extended] | v0.137.0 |
|***Providers***||||
| [envprovider](https://github.com/open-telemetry/opentelemetry-collector/tree/main/confmap/provider/envprovider) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v1.43.0 |
| [fileprovider](https://github.com/open-telemetry/opentelemetry-collector/tree/main/confmap/provider/fileprovider) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v1.43.0 |
| [httpprovider](https://github.com/open-telemetry/opentelemetry-collector/tree/main/confmap/provider/httpprovider) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v1.43.0 |
| [httpsprovider](https://github.com/open-telemetry/opentelemetry-collector/tree/main/confmap/provider/httpsprovider) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v1.35.0 |
| [yamlprovider](https://github.com/open-telemetry/opentelemetry-collector/tree/main/confmap/provider/yamlprovider) | [OTel Core Repo](https://github.com/open-telemetry/opentelemetry-collector) | [Core] | v1.43.0 |


% end:edot-collector-components-table

[Extended]: opentelemetry://reference/compatibility/nomenclature.md#extended-components
[Core]: opentelemetry://reference/compatibility/nomenclature.md#core-components
