---
navigation_title: Tracing collection
description: Learn how to configure and customize tracing collection through the Elastic Distribution of OpenTelemetry Collector.
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

# Configure tracing collection

Learn how to configure and customize tracing collection through the {{edot}} Collector.

## OTLP traces

Any application instrumented with OpenTelemetry SDKs can forward traces to the EDOT Collector using the [OTLP receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver). This is the recommended method for collecting application traces.

The following minimal configuration receives traces over gRPC and HTTP, enriches them for the Elastic {{product.apm}} UIs, and exports them to {{es}}:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

connectors:
  elasticapm:

processors:
  elasticapm:

exporters:
  elasticsearch/otel:
    endpoints: ["${env:ELASTIC_ENDPOINT}"]
    api_key: ${env:ELASTIC_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [elasticapm, elasticsearch/otel]
    metrics/aggregated-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [elasticsearch/otel]
```

:::{note}
Both the [`elasticapm` processor](../components/elasticapmprocessor.md) and the [`elasticapm` connector](../components/elasticapmconnector.md) are required for Elastic {{product.apm}} UIs to work properly. The processor enriches trace data with additional attributes, while the connector generates pre-aggregated {{product.apm}} metrics from tracing data.

As they aren't included in the OpenTelemetry [Collector Contrib repository](https://github.com/open-telemetry/opentelemetry-collector-contrib), you can:

* Use the EDOT Collector with the available configuration to ingest data into {{es}}.
* [Build a custom, EDOT-like Collector](/reference/edot-collector/custom-collector.md) for ingesting data into {{es}}.
* Use Elastic's [managed OTLP endpoint](docs-content://solutions/observability/get-started/opentelemetry/quickstart/serverless/index.md) that does the enrichment for you.
:::

## Tail-based sampling [tail-based-sampling]

```{applies_to}
edot_collector: preview 9.2+
```

Tail-based sampling analyzes a complete trace before deciding whether to keep it, enabling intelligent decisions based on factors like errors or high latency. This is different from head-based sampling, which makes an early decision at the start of a trace.

Within the OpenTelemetry Collector, any processor that generates metrics from traces must run before the tail-sampling processor. If sampling happens first, metrics will be calculated on an incomplete data set, leading to inaccurate and misleading reporting.

:::{tip}
To enforce a specific order of calculations and sampling decisions in the EDOT Collector, you can use the [Forward connector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector). Split the traces pipeline in two steps using the connector, with the first part applying calculations and the second part applying the tail-based sampling decision.
:::

### Create a two-step trace pipeline

Configure a two-step trace pipeline, ensuring that the first step includes the `elasticapm` connector and `forward` connector under the `exporters` section, and that the second step includes the `tail_sampling` processor.

The following configuration is a full working example with the `elasticapm` processor and connector, tail-based sampling, and aggregated {{product.apm}} metrics:

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
  forward:

processors:
  elasticapm: {}
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      [
        {
          name: latency-5000ms-10000ms,
          type: latency,
          latency: {threshold_ms: 5000, upper_threshold_ms: 10000}
        }
      ]

exporters:
  debug: {}
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    traces/1-process-elastic:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [debug, elasticapm, forward]
    traces/2-process-tbs:
      receivers: [forward]
      processors: [tail_sampling]
      exporters: [debug, elasticsearch/otel]
    metrics/aggregated-otel-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [debug, elasticsearch/otel]
```

### Scale with a load-balancing Collector

To horizontally scale collectors with tail-based sampling turned on, all traces should go through a load-balancing Collector in front of the downstream tail-sampling collectors. Set the `traceID` as the routing key in the load-balancing Collector so that all traces belonging to the same trace ID go to the same downstream tail-sampling Collector.

:::::{tab-set}

::::{tab-item} Load-balancing Collector
```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

exporters:
  loadbalancing:
    protocol:
      otlp:
    resolver:
      static:
        hostnames: [http://localhost:4320, http://localhost:4321]
    routing_key: traceID

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [loadbalancing]
```
::::

::::{tab-item} Downstream Collector
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
  forward:

processors:
  elasticapm: {}
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      [
        {
          name: latency-5000ms-10000ms,
          type: latency,
          latency: {threshold_ms: 5000, upper_threshold_ms: 10000}
        }
      ]

exporters:
  debug: {}
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}
    mapping:
      mode: otel

service:
  pipelines:
    traces/1-process-elastic:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [debug, elasticapm, forward]
    traces/2-process-tbs:
      receivers: [forward]
      processors: [tail_sampling]
      exporters: [debug, elasticsearch/otel]
    metrics/aggregated-otel-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [debug, elasticsearch/otel]
```
::::
:::::

## Resources

To learn more about tail-based sampling in the OpenTelemetry Collector, refer to the [Tail sampling OTel documentation](https://opentelemetry.io/docs/concepts/sampling/#tail-sampling).
