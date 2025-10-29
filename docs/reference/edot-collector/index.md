---
navigation_title: EDOT Collector
description: Introduction to the Elastic Distribution of OpenTelemetry (EDOT) Collector, a curated and supported distribution of the OpenTelemetry Collector.
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

# Elastic Distribution of OpenTelemetry Collector

The {{edot}} (EDOT) Collector is an open-source distribution of the OpenTelemetry Collector. 

## Get started

To install the EDOT Collector with basic settings in your environment, follow the [quickstart guides](docs-content://solutions/observability/get-started/opentelemetry/quickstart/index.md).

## Deployment modes
 
You can deploy the EDOT Collector in different modes to meet your architectural needs. The two primary Collector modes are Agent and Gateway. Depending on your Elastic deployment type, various EDOT Collector instances might be required in each mode to support the target architecture. Refer to [Deployment modes](/reference/edot-collector/modes.md) for more details.

## Configure the Collector

You can configure the EDOT Collector to use the standard OTel Collector configuration file or `values.yml` file if you have deployed it using Helm.

For full details on each option, see [Configuration](/reference/edot-collector/config/index.md)

## Collector components

Built on OpenTelemetry’s modular architecture, the EDOT Collector offers a curated and fully supported selection of components designed for production-grade reliability.

Refer to [Components](/reference/edot-collector/components.md) for the full list of components embedded in the EDOT Collector.

To request a component to be added to EDOT Collector, submit a [GitHub issue here](https://github.com/elastic/elastic-agent/issues/new/choose).

## Limitations 

The EDOT Collector inherits the same limitations from the contrib components. Refer to [Limitations](opentelemetry://reference/compatibility/limitations.md) for a complete list.

## License

For details on the EDOT Collector license, see the [LICENSE.txt](https://github.com/elastic/elastic-agent/blob/main/LICENSE.txt) file.
