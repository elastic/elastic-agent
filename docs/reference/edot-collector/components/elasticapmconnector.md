---
navigation_title: Elastic APM connector
description: Elastic APM connector is an OpenTelemetry Collector component that generates pre-aggregated APM metrics from trace data.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector:
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# Elastic APM connector

The Elastic {{product.apm}} connector generates pre-aggregated metrics from OpenTelemetry trace data. These metrics provide essential performance insights and enable key {{product.apm}} features like service maps, transaction histograms, and service-level indicators, all while significantly reducing storage requirements compared to raw trace data.

The connector works together with the [Elastic {{product.apm}} processor](elasticapmprocessor.md), which enriches OpenTelemetry traces with Elastic-specific attributes to ensure optimal compatibility with Elastic {{product.apm}} UIs.

## Default usage in EDOT

The `elasticapm` connector is included by default in EDOT Collector deployments that ingest trace data directly into {{es}}. It's not needed when using the [{{motlp}}](opentelemetry://reference/motlp.md), as the metric aggregation happens server-side.

### Standalone deployments

In standalone deployments, the Elastic APM connector is used in both agent and gateway modes:

**Agent mode**: The connector is part of the default [application and traces collection pipeline](../config/default-config-standalone.md#application-and-traces-collection-pipeline). It receives trace data from the pipeline, generates metrics, and forwards them to {{es}}.

**Gateway mode**: The connector is part of the [Gateway mode pipeline](../config/default-config-standalone.md#gateway-mode), where it generates metrics from traces received from other collectors running in agent mode before ingesting them into {{es}}.

:::{note}
:applies_to: edot_collector: ga 9.2
The `elasticapm` connector replaces the deprecated `elastictrace` connector. If you're upgrading from an older version, update your configuration to use `elasticapm` instead of `elastictrace`.
:::

### Kubernetes deployment

In Kubernetes, the Elastic APM connector runs in the [Gateway collectors pipeline](../config/default-config-k8s.md#gateway-collectors-pipeline) when using direct ingestion to {{es}}. The Gateway receives traces from DaemonSet collectors, generates APM metrics, and writes both metrics and traces to {{es}}.

For more details about the Kubernetes configuration, refer to [Default configuration (Kubernetes)](../config/default-config-k8s.md).

## Example configuration

The Elastic APM connector typically requires minimal configuration. Usually, an empty configuration block is sufficient:

```yaml
connectors:
  elasticapm: {}
```

When combined with the `elasticapm` processor in a complete pipeline:

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

In this configuration, the `elasticapm` connector appears as both an exporter in the traces pipeline to generate {{product.apm}} metrics and as a receiver in the metrics pipeline to forward those metrics to {{es}}.

## Generated metrics

The Elastic APM connector generates the following types of aggregated metrics from trace data:

| Metric Type | Description |
|------------|-------------|
| Transaction metrics | Aggregated statistics about service transactions, including throughput, latency distributions, and success rates. These metrics power service overview pages and transaction group views. |
| Service destination metrics | Metrics that track dependencies between services, showing how services communicate with databases, message queues, and other external systems. These metrics are used to build service maps. |
| Span metrics | Detailed metrics about individual span operations, including database queries, HTTP calls, and other operations. These provide granular performance insights for specific operations. |
| Service summary metrics | High-level service health metrics including error rates, throughput, and overall latency. These metrics enable quick health checks and alerting. |

All metrics are generated with appropriate aggregation periods and follow Elastic's metric schema for seamless integration with {{product.apm}} UIs.

## Aggregation intervals

The connector aggregates metrics over configurable time intervals. The default aggregation period is 1 minute, which provides a good balance between metric granularity and storage efficiency.

You can adjust the aggregation interval using the `aggregation_interval` setting:

```yaml
connectors:
  elasticapm:
    aggregation_interval: 1m
```

:::{note}
Shorter aggregation intervals provide more granular metrics but increase storage requirements. Longer intervals reduce storage needs but might lose important short-term patterns.
:::

## Best practices

Follow these recommendations when using the Elastic APM connector:

* **Always pair with the elasticapm processor**: The connector and processor work together to provide the full Elastic {{product.apm}} experience. The processor enriches traces while the connector generates {{product.apm}} metrics. Include both in your pipeline configuration for complete functionality.

* **Place the connector as an exporter in the traces pipeline**: Configure the Elastic APM connector as an exporter in your traces pipeline, alongside your final data destination. This ensures the connector receives processed trace data and can generate accurate metrics.

* **Create a separate metrics pipeline for connector output**: Set up a dedicated metrics pipeline with the connector as the receiver. This isolates metric handling and makes it easier to apply metric-specific processing if needed.

* **Use only for direct {{es}} ingestion**: If you're using the {{motlp}}, you don't need the Elastic APM connector, because the endpoint handles metric aggregation automatically. Using both can cause conflicts or duplicate metrics.

* **Keep the connector updated**: The Elastic APM connector evolves with new Elastic {{product.apm}} features. Keep your EDOT Collector version current to benefit from the latest enhancements and compatibility improvements.

* **Monitor connector performance**: The connector aggregates metrics in memory before flushing. For high-throughput environments, monitor memory usage and adjust the aggregation interval or deployment resources as needed.

## Limitations

Be aware of these constraints and behaviors when using the Elastic APM connector:

* **Required for Elastic {{product.apm}} metrics**: Without the Elastic APM connector, you'll only have raw trace data in {{es}}. Service maps, transaction histograms, and other metric-driven {{product.apm}} features require the pre-aggregated metrics that this connector generates.

* **Not available in contrib OTel Collector**: The Elastic APM connector is an Elastic-specific component not included in the standard OpenTelemetry Collector or Collector Contrib distributions. To use it, you must either use EDOT Collector or [build a custom collector](../custom-collector.md) that includes Elastic's components.

* **Memory usage scales with cardinality**: The connector maintains in-memory aggregations for unique combinations of service names, transaction names, and other dimensions. High-cardinality data (many unique values) increases memory requirements. Monitor memory usage in high-cardinality environments.

* **Minimal configuration options**: Unlike some connectors, the Elastic APM connector operates with mostly fixed behavior and offers few configuration parameters. While this simplifies setup, it also means you have limited ability to customize the aggregation logic.

* **Replaces elastictrace connector**: If you're upgrading from versions prior to 9.2, be aware that `elastictrace` is deprecated. Update your configurations to use `elasticapm` for continued support and new features.

## Resources

* [Contrib component: elasticapmconnector](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector)
* [Elastic {{product.apm}} processor](elasticapmprocessor.md)
* [Default configuration (Standalone)](../config/default-config-standalone.md#application-and-traces-collection-pipeline)
* [Default configuration (Kubernetes)](../config/default-config-k8s.md)
* [Build a custom collector with Elastic components](../custom-collector.md)

