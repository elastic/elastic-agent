---
navigation_title: Elastic Agent
description: Elastic Agent includes a built-in OpenTelemetry Collector for collecting and forwarding traces, metrics, and logs to Elastic Observability.
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

# {{agent}}

:::{note}
Starting with version 9.5, the EDOT Collector is part of {{agent}}. If you're on an earlier version, the product was called the EDOT Collector — the configuration and components are the same.
:::

{{agent}} includes a built-in OpenTelemetry Collector: an open-source distribution of the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/).

## Get started

To install {{agent}} with basic settings in your environment, follow the [quickstart guides](docs-content://solutions/observability/get-started/opentelemetry/quickstart/index.md).

## Deployment modes

You can deploy {{agent}} in different modes to meet your architectural needs. The two primary modes are Agent and Gateway. Depending on your Elastic deployment type, various {{agent}} instances might be required in each mode to support the target architecture. Refer to [Deployment modes](/reference/edot-collector/modes.md) for more details.

## Configure

You can configure {{agent}} to use the standard OTel Collector configuration file or `values.yml` file if you have deployed it using Helm.

For full details on each option, see [Configuration](/reference/edot-collector/config/index.md).

## Components

Built on OpenTelemetry's modular architecture, {{agent}} offers a curated and fully supported selection of components designed for production-grade reliability.

Refer to [Components](/reference/edot-collector/components.md) for the full list of components included in {{agent}}.

To request a component to be added, submit a [GitHub issue](https://github.com/elastic/elastic-agent/issues/new/choose).

## Limitations

{{agent}} inherits limitations from the contrib components it includes. Refer to [Limitations](opentelemetry://reference/compatibility/limitations.md) for a complete list.

## License

For details on the license, see the [LICENSE.txt](https://github.com/elastic/elastic-agent/blob/main/LICENSE.txt) file.
