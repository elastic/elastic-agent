---
navigation_title: Tracing collection
description: Learn how to configure and customize tracing collection through the {{agent}}.
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

Learn how to configure and customize tracing collection through the {{agent}}.

## OTLP traces

Any application instrumented with OpenTelemetry SDKs can forward traces to the {{agent}} using the [OTLP receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver). This is the recommended method for collecting application traces.

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

* Use the {{agent}} with the available configuration to ingest data into {{es}}.
* [Build a custom, {{agent}}-like Collector](/reference/edot-collector/custom-collector.md) for ingesting data into {{es}}.
* Use Elastic's [managed OTLP endpoint](docs-content://solutions/observability/get-started/opentelemetry/quickstart/serverless/index.md) that does the enrichment for you.
:::

## Tail-based sampling [tail-based-sampling]

```{applies_to}
edot_collector: preview 9.2+
```

Tail-based sampling analyzes a complete trace before deciding whether to keep it, enabling intelligent decisions based on factors like errors or high latency. This is different from head-based sampling, which makes an early decision at the start of a trace.

Within the OpenTelemetry Collector, any processor that generates metrics from traces must run before the tail-sampling processor. If sampling happens first, metrics will be calculated on an incomplete data set, leading to inaccurate and misleading reporting.

:::{tip}
To enforce a specific order of calculations and sampling decisions in the {{agent}}, you can use the [Forward connector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector). Split the traces pipeline in two steps using the connector, with the first part applying calculations and the second part applying the tail-based sampling decision.
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
  elasticapm: {} # Generates APM metrics from spans enriched by the processor
  forward:

processors:
  elasticapm: {} # Enriches spans before the connector generates APM metrics
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      - name: errors
        type: status_code
        status_code:
          status_codes: [ERROR]
      - name: probabilistic-10-percent
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

exporters:
  debug: {}
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}

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

### Send edge-aggregated data to Managed OTLP

Run this configuration on a self-managed {{agent}} in [Gateway mode](../modes.md#edot-collector-as-gateway). OpenTelemetry SDKs and upstream Collectors send telemetry to this gateway, which performs tail-based sampling and {{product.apm}} metric aggregation before exporting to an Elastic Cloud {{motlp}}. The gateway requires a Managed OTLP endpoint and API key. If you send telemetry directly to a self-managed {{es}} deployment instead, use the [two-step direct-to-Elasticsearch configuration](#create-a-two-step-trace-pipeline).

A dedicated OTLP exporter adds the `x-elastic-apm-aggregation-processed: "true"` header. The {{motlp}} uses this header to avoid aggregating the telemetry again. Use this exporter only for post-sampling traces, logs and metrics processed by the edge `elasticapm` connector, and metrics produced by the connector. Send unrelated host metrics, platform logs, and other telemetry through an exporter without the header.

Before deploying this configuration in production, review [Scaling tail-based sampling](#scaling-tail-based-sampling).

The following configuration is a full working example:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

connectors:
  elasticapm: {} # Generates APM metrics from spans enriched by the processor
  forward:

processors:
  elasticapm: {} # Enriches spans before the connector generates APM metrics
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      - name: errors
        type: status_code
        status_code:
          status_codes: [ERROR]
      - name: probabilistic-10-percent
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

exporters:
  otlp_grpc/managed_otlp_aggregated:
    endpoint: ${env:ELASTIC_OTLP_ENDPOINT}
    headers:
      Authorization: ApiKey ${env:ELASTIC_API_KEY}
      x-elastic-apm-aggregation-processed: "true"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [elasticapm, otlp_grpc/managed_otlp_aggregated]
    logs:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [elasticapm, otlp_grpc/managed_otlp_aggregated]
    traces/1-process-elastic:
      receivers: [otlp]
      processors: [elasticapm]
      exporters: [elasticapm, forward]
    traces/2-process-tbs:
      receivers: [forward]
      processors: [tail_sampling]
      exporters: [otlp_grpc/managed_otlp_aggregated]
    metrics/aggregated-otel-metrics:
      receivers: [elasticapm]
      processors: []
      exporters: [otlp_grpc/managed_otlp_aggregated]
```

### Scaling tail-based sampling [scaling-tail-based-sampling]

The [tail-sampling processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor) holds pending traces in memory until it makes a sampling decision. `decision_wait` controls how long the processor waits after receiving the first span of a trace. Longer waits accommodate late spans but retain traces for longer. `num_traces` limits how many traces can be held in memory; when that capacity is exhausted, traces can be evicted before a decision is made.

Size `num_traces` above the peak number of new traces received during `decision_wait`, with headroom for traffic bursts and late spans. Validate memory usage and early evictions under representative load before production.

The {{agent}} does not currently include the upstream experimental [Pebble tail-storage extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/tailstorage/pebbletailstorageextension), so pending traces are buffered in memory. The `elasticapm` connector maintains separate metric aggregation state. For production workloads, configure its [`aggregation.directory`](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector#configuration) to store that state on disk.

#### Distribute traces with a load-balancing Collector

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
  elasticapm: {} # Generates APM metrics from spans enriched by the processor
  forward:

processors:
  elasticapm: {} # Enriches spans before the connector generates APM metrics
  tail_sampling:
    decision_wait: 10s
    num_traces: 100
    expected_new_traces_per_sec: 10
    policies:
      - name: errors
        type: status_code
        status_code:
          status_codes: [ERROR]
      - name: probabilistic-10-percent
        type: probabilistic
        probabilistic:
          sampling_percentage: 10

exporters:
  debug: {}
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}

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
