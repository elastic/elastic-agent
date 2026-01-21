---
navigation_title: Elastic APM processor
description: The Elastic APM processor is an OpenTelemetry Collector component that enriches OTel data for optimal use with Elastic APM.
applies_to:
  stack: ga 9.2+
  serverless:
    observability:
  product:
    edot_collector: ga 9.2+
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# Elastic {{product.apm}} processor

The Elastic {{product.apm}} processor enriches OpenTelemetry trace data with Elastic-specific attributes and metadata, ensuring optimal compatibility with Elastic {{product.apm}} UIs and functionality. It bridges the gap between OpenTelemetry's trace format and Elastic's expectations, enabling features like service maps, transaction groups, and enhanced trace visualization.

The processor works together with the [Elastic {{product.apm}} connector](elasticapmconnector.md), which generates pre-aggregated {{product.apm}} metrics from trace data.

## Default usage in EDOT

The `elasticapmprocessor` is included by default in EDOT Collector deployments that ingest trace data directly into {{es}}. It's not needed when using the [{{motlp}}](opentelemetry://reference/motlp.md), as the enrichment happens server-side.

### Standalone deployments

In standalone deployments, the Elastic APM processor is used in both agent and gateway modes:

**Agent mode**: The processor is part of the default [application and traces collection pipeline](../config/default-config-standalone.md#application-and-traces-collection-pipeline). It processes trace data received from OpenTelemetry SDKs before exporting to {{es}}.

**Gateway mode**: The processor is part of the [Gateway mode pipeline](../config/default-config-standalone.md#gateway-mode), where it enriches traces received from other collectors running in agent mode before ingesting them into {{es}}.

:::{note}
The `elasticapm` processor replaces the deprecated `elastictrace` processor. If you're upgrading from an older version, update your configuration to use `elasticapm` instead of `elastictrace`.
:::

### Kubernetes deployment

In Kubernetes, the Elastic APM processor runs in the [Gateway collectors pipeline](../config/default-config-k8s.md#gateway-collectors-pipeline) when using direct ingestion to {{es}}. The Gateway receives traces from DaemonSet collectors and enriches them before writing to {{es}}.

For more details about the Kubernetes configuration, refer to [Default configuration (Kubernetes)](../config/default-config-k8s.md).

## Example configuration

The Elastic APM processor typically requires minimal configuration. Usually, an empty configuration block is sufficient:

```yaml
processors:
  elasticapm: {}
```

When combined with the `elasticapm` connector in a complete pipeline:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

connectors:
  elasticapm: {}

processors:
  batch:
    send_batch_size: 1000
    timeout: 1s
  elasticapm: {}

exporters:
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, elasticapm]
      exporters: [elasticapm, elasticsearch/otel]
    
    metrics/aggregated-otel-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [elasticsearch/otel]
```

The `elasticapm` connector appears as both an exporter in the traces pipeline (to generate {{product.apm}} metrics) and as a receiver in the metrics pipeline (to forward those metrics to {{es}}).

## Key enrichments

The Elastic APM processor enhances trace data with the following capabilities:

| Enrichment | Description |
|------------|-------------|
| Transaction grouping | Adds or modifies attributes to properly group transactions in Elastic {{product.apm}} UIs. |
| Service metadata | Ensures service name, version, and environment are correctly formatted. |
| Span metadata | Enriches spans with Elastic-specific fields for proper rendering in trace views. |
| Error handling | Transforms error information to align with Elastic's error model. |
| Data stream routing | Adds necessary attributes for proper data stream routing in {{es}}. |

For detailed information about specific attributes and transformations, refer to the [contrib `elasticapmprocessor` documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticapmprocessor).

## Best practices

Follow these recommendations when using the Elastic APM processor:

* **Always pair with the elasticapm connector**: The processor and connector work together to provide the full Elastic {{product.apm}} experience. The processor enriches traces while the connector generates {{product.apm}} metrics. Include both in your pipeline configuration for complete functionality.

* **Place after batching in the pipeline**: Configure the Elastic APM processor after the batch processor to ensure optimal throughput. Batching first reduces the number of processing operations.

* **Use only for direct {{es}} ingestion**: If you're using the {{motlp}}, you don't need the Elastic APM processor, because the endpoint handles enrichment automatically. Using both can cause conflicts or duplicate processing.

* **Keep the processor updated**: The Elastic APM processor evolves with new Elastic {{product.apm}} features. Keep your EDOT Collector version current to benefit from the latest enhancements and compatibility improvements.

* **Configure OTel SDKs with semantic conventions**: The processor relies on OpenTelemetry semantic conventions to identify and enrich trace data correctly. Ensure your SDKs follow standard conventions for service name, span attributes, and resource attributes.

## Limitations

Be aware of these constraints and behaviors when using the Elastic APM processor:

* **Required for Elastic {{product.apm}} UIs**: Without the Elastic APM processor, OpenTelemetry traces will be stored in {{es}} but may not render correctly in Elastic {{product.apm}} UIs. Service maps, transaction groups, and other {{product.apm}}-specific visualizations depend on the enrichments this processor provides.

* **Not available in contrib OTel Collector**: The Elastic APM processor is an Elastic-specific component not included in the standard OpenTelemetry Collector or Collector Contrib distributions. To use it, you must either use EDOT Collector or [build a custom collector](../custom-collector.md) that includes Elastic's components.


* **Minimal configuration options**: Unlike some processors, the Elastic APM processor operates with fixed behavior and offers few configuration parameters. While this simplifies setup, it also means you can't customize the enrichment logic.

* **Replaces elastictrace processor**: If you're upgrading from versions prior to 9.2, be aware that `elastictrace` is deprecated. Update your configurations to use `elasticapm` for continued support and new features.

## Resources

* [Contrib component: elasticapmprocessor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticapmprocessor)
* [Elastic {{product.apm}} connector](elasticapmconnector.md)
* [Default configuration (Standalone)](../config/default-config-standalone.md#application-and-traces-collection-pipeline)
* [Default configuration (Kubernetes)](../config/default-config-k8s.md)
* [Build a custom collector with Elastic components](../custom-collector.md)

