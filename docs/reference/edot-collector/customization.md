---
navigation_title: Customization
description: Options for customizing Elastic Agent, including building a custom Collector or requesting new components.
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

# {{agent}} customization

{{agent}} comes with a [curated list](/reference/edot-collector/components.md) of OTel Collector components and some opinionated [configuration samples](https://github.com/elastic/elastic-agent/tree/main/internal/edot/samples).

If your use case requires additional components, you have two options:

1. [Build a custom Collector](/reference/edot-collector/custom-collector.md)
2. [Open a request](https://github.com/elastic/elastic-agent/issues/new/choose) to add those components to {{agent}}.

Requests for adding new components will be reviewed on the basis of popularity, technical suitability, and other criteria.

For instructions on how to build a custom Collector, refer to the [OpenTelemetry documentation](https://opentelemetry.io/docs/collector/custom-collector/).

:::{warning}
Custom Collector builds are not covered through [Elastic's Support](https://www.elastic.co/support_policy).
:::
