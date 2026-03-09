---
navigation_title: Tail-based sampling
description: Configure the EDOT Collector for tail-based sampling (TBS).
applies_to:
  stack: preview 9.2+
  serverless:
    observability:
  product:
    edot_collector: preview 9.2+
products:
  - id: observability
  - id: edot-collector
---

# Configure tail-based sampling

Tail-based sampling analyzes a complete trace before deciding whether to keep it, enabling intelligent decisions based on factors like errors or high latency. This is different from head-based sampling, which makes an early decision at the start of a trace.

Within the OpenTelemetry Collector, any processor that generates metrics from traces must run before the tail-sampling processor. If sampling happens first, metrics will be calculated on an incomplete data set, leading to inaccurate and misleading reporting.

To enforce a specific order of calculations and sampling decisions in the EDOT Collector, you can use the [Forward connector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector). Split the traces pipeline in two steps using the connector, with the first part applying calculations and the second part applying the tail-based sampling decision.

## Create a two-step trace pipeline

Configure a two-step trace pipeline, ensuring that the first step includes the `elasticapm` connector and `forward` connector under `exporters` section, and that the second step includes the `tail_sampling` processor.

```yaml
connectors:
  elasticapm: {} # Elastic APM Connector
  forward: # Forward connector necessary for tail-based sampling

processors:
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
service:
  pipelines:
    traces/1-process-elastic:
      receivers: [ otlp ]
      processors: [ elasticapm ]
      exporters: [ elasticapm, forward ]
    traces/2-process-tbs:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```

## Configuration for a load-balancing Collector

To horizontally scale collectors with tail-based sampling turned on, all traces should go through a load-balancing Collector in front of the downstream tail-sampling collectors. Set the `traceID` as the routing key in the load-balancing Collector so that all traces belonging to the same trace ID go to the same downstream tail-sampling Collector.

::::{tab-set}

:::{tab-item} Load-balancing Collector
```yaml
exporters:
  loadbalancing:
    routing_key: traceID
```
:::

:::{tab-item} Downstream Collector
```yaml
connectors:
  elasticapm: {} # Elastic APM Connector
  forward: # Forward connector necessary for tail-based sampling

processors:
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
service:
  pipelines:
    traces/1-process-elastic:
      receivers: [ otlp ]
      processors: [ elasticapm ]
      exporters: [ elasticapm, forward ]
    traces/2-process-tbs:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```
:::
::::

## Resources

To learn more about tail-based sampling in the OpenTelemetry Collector, refer to the [Tail sampling OTel documentation](https://opentelemetry.io/docs/concepts/sampling/#tail-sampling).
