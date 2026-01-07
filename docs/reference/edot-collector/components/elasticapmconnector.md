---
navigation_title: Elastic {{product.apm}} connector
description: The Elastic {{product.apm}} connector is an OpenTelemetry Collector component that generates pre-aggregated APM metrics from trace data.
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

# Elastic {{product.apm}} connector

The Elastic {{product.apm}} connector generates pre-aggregated metrics from OpenTelemetry trace data. These metrics enable key {{product.apm}} features like service maps, transaction histograms, and service-level indicators with fast query performance. Instead of calculating metrics on the fly from potentially millions of transactions, the {{product.apm}} UIs can query pre-computed metric documents for quick data visualization.

The connector works together with the [Elastic {{product.apm}} processor](elasticapmprocessor.md), which enriches OpenTelemetry traces with Elastic-specific attributes to ensure optimal compatibility with Elastic {{product.apm}} UIs.

## Default usage in EDOT

The `elasticapm` connector is included by default in EDOT Collector deployments that ingest trace data directly into {{es}}. It's not needed when using the [{{motlp}}](opentelemetry://reference/motlp.md), as the metric aggregation happens server-side.

### Standalone deployments

In standalone deployments, the Elastic {{product.apm}} connector is used in both agent and gateway modes:

* **Agent mode**: The connector is part of the default [application and traces collection pipeline](../config/default-config-standalone.md#application-and-traces-collection-pipeline). It receives trace data from the pipeline, generates metrics, and forwards them to {{es}}.

* **Gateway mode**: The connector is part of the [Gateway mode pipeline](../config/default-config-standalone.md#gateway-mode), where it generates metrics from traces received from other collectors running in agent mode before ingesting them into {{es}}.


### Kubernetes deployment

In Kubernetes, the Elastic {{product.apm}} connector runs in the [Gateway collectors pipeline](../config/default-config-k8s.md#gateway-collectors-pipeline) when using direct ingestion to {{es}}. The Gateway receives traces from DaemonSet collectors, generates {{product.apm}} metrics, and writes both metrics and traces to {{es}}.

For more details about the Kubernetes configuration, refer to [Default configuration (Kubernetes)](../config/default-config-k8s.md).

## Example configuration

The Elastic {{product.apm}} connector typically requires minimal configuration. Usually, an empty configuration block is sufficient:

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

The Elastic {{product.apm}} connector generates the following types of aggregated metrics from trace data:

| Metric Type | Description |
|------------|-------------|
| Transaction metrics | Aggregated statistics about service transactions, including throughput, latency distributions, and success rates. These metrics power service overview pages and transaction group views. |
| Service destination metrics | Metrics that track dependencies between services, showing how services communicate with databases, message queues, and other external systems. These metrics are used to build service maps. |
| Span metrics | Detailed metrics about individual span operations, including database queries, HTTP calls, and other operations. These provide granular performance insights for specific operations. |
| Service summary metrics | High-level service health metrics including error rates, throughput, and overall latency. These metrics enable quick health checks and alerting. |

All metrics are generated with appropriate aggregation periods and follow Elastic's metric schema for seamless integration with {{product.apm}} UIs.

## Aggregation intervals

The connector aggregates metrics over multiple time intervals to provide different granularities for analysis. By default, metrics are aggregated at three intervals: 1 minute, 10 minutes, and 60 minutes.

## Best practices

Follow these recommendations when using the Elastic {{product.apm}} connector:

* **Always pair with the elasticapm processor**: The connector and processor work together to provide the full Elastic {{product.apm}} experience. The processor enriches traces while the connector generates {{product.apm}} metrics. Include both in your pipeline configuration for complete functionality.

* **Place the connector as an exporter in the traces pipeline**: Configure the Elastic {{product.apm}} connector as an exporter in your traces pipeline, alongside your final data destination. This ensures the connector receives processed trace data and can generate accurate metrics.

* **Create a separate metrics pipeline for connector output**: Set up a dedicated metrics pipeline with the connector as the receiver. This isolates metric handling and makes it easier to apply metric-specific processing if needed.

* **Use only for direct {{es}} ingestion**: If you're using the {{motlp}}, you don't need the Elastic {{product.apm}} connector, because the endpoint handles metric aggregation automatically. Using both can cause conflicts or duplicate metrics.

* **Keep the connector updated**: The Elastic {{product.apm}} connector evolves with new Elastic {{product.apm}} features. Keep your EDOT Collector version current to benefit from the latest enhancements and compatibility improvements.

* **Monitor connector performance**: The connector aggregates metrics in memory before flushing. For high-throughput environments, monitor memory usage and adjust the aggregation interval or deployment resources as needed.

## Limitations

Be aware of these constraints and behaviors when using the Elastic {{product.apm}} connector:

* **Required for Elastic {{product.apm}} metrics**: Without the Elastic {{product.apm}} connector, you'll only have raw trace data in {{es}}. Service maps, transaction histograms, and other metric-driven {{product.apm}} features might require the pre-aggregated metrics that this connector generates.

* **Not available in contrib OTel Collector**: The Elastic {{product.apm}} connector is an Elastic-specific component not included in the standard OpenTelemetry Collector or Collector Contrib distributions. To use it, you must either use EDOT Collector or [build a custom collector](../custom-collector.md) that includes Elastic's components.

* **Memory usage scales with cardinality**: The connector maintains in-memory aggregations for unique combinations of service names, transaction names, and other dimensions. High-cardinality data (many unique values) increases memory requirements. Monitor memory usage in high-cardinality environments.

* **Minimal configuration options**: Unlike some connectors, the Elastic {{product.apm}} connector operates with mostly fixed behavior and offers few configuration parameters. While this simplifies setup, it also means you have limited ability to customize the aggregation logic.


## Troubleshooting

Read the following sections to troubleshoot issues with the Elastic {{product.apm}} connector.

:::{dropdown} Storage spikes from high-cardinality data
If you detect unexpected spikes in storage usage for {{product.apm}} metrics, high-cardinality data is often the cause. The connector aggregates metrics across multiple time intervals, and the volume of aggregated metrics is directly proportional to the cardinality of your data. The more unique combinations of service names, transaction names, and other dimensions, the more metric documents are produced.

High cardinality in aggregations often points to an instrumentation issue, such as a field with many unique values that shouldn't vary. For example, including user IDs or request IDs in transaction names.

#### Solution

To limit the cardinality of aggregations and reduce storage usage, you can configure limits lower than the defaults. The connector supports four cardinality limits:

| Limit | Description | Default |
|-------|-------------|---------|
| `resource` | Maximum cardinality of resources | 8000 |
| `scope` | Maximum cardinality of scopes within a resource | 4000 |
| `metric` | Maximum cardinality of metrics within a scope | 4000 |
| `datapoint` | Maximum cardinality of datapoints within a metric | 4000 |

Here's an example configuration that halves all the default cardinality limits:

```yaml
connectors:
  elasticapm:
    aggregation:
      limits:
        resource:
          max_cardinality: 4000
        scope:
          max_cardinality: 2000
        metric:
          max_cardinality: 2000
        datapoint:
          max_cardinality: 2000
```

When configured limits are reached, additional metrics are placed into a separate overflow bucket. This bounds the resources consumed, but if overflow occurs frequently, it usually indicates an instrumentation problem that should be addressed at the source.

#### Detecting overflow

To check if overflow is occurring, look for overflow-related log messages from the connector. Frequent overflow events suggest that your cardinality limits are being exceeded regularly, which might affect the completeness of your {{product.apm}} metrics.

If overflow is happening consistently, consider:

1. Investigating the source of high-cardinality data and fixing the instrumentation.
2. Lowering the `max_cardinality` settings as a temporary measure to bound resource usage.

Lowering cardinality limits should be a last resort after confirming that high cardinality is expected for your use case and cannot be reduced through better instrumentation practices.
:::

## Resources

* [Contrib component: elasticapmconnector](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector)
* [Elastic {{product.apm}} processor](elasticapmprocessor.md)
* [Default configuration (Standalone)](../config/default-config-standalone.md#application-and-traces-collection-pipeline)
* [Default configuration (Kubernetes)](../config/default-config-k8s.md)
* [Build a custom collector with Elastic components](../custom-collector.md)

