---
navigation_title: Tail-based sampling
description: Configure the EDOT Collector for tail-based sampling (TBS).
applies_to:
  deployment:
      ess: ga 9.2
  stack: ga 9.2
  serverless:
    observability:
  product:
    edot_collector: ga
products:
  - id: observability
  - id: edot-collector
---

# Configure tail-based sampling

Tail-based sampling is where the decision to sample a trace takes place by considering all or most of the spans within the trace. This is in contrast to Head-based sampling, which is on the client-side where traces are created.

Because metrics are calculated and aggregations are performed on trace data in the EDOT collector, some specific configuration is required to ensure that the tail sampling decisions are made after these calculations.
Otherwise, the metrics and aggregations would be incorrect due to the partial representation of traces.

To enforce a specific order of calculations and sampling decisions in the EDOT Collector, you can use the [Forward connector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector). Split the traces pipeline in two steps using the connector, with the first part applying calculations and the second part applying the tail-based sampling decision.

## Configure the EDOT Collector to have a two-part trace pipeline

Configure a two-part trace pipeline, ensuring that the first one includes the `elasticapm` exporter and `forward` exporter and the second one includes the `tail_sampling` processor.

:::{tab-item} EDOT Collector config
```yaml
processors:
  tail_sampling:
    decision_wait: 5s
    num_traces: 50000
    expected_new_traces_per_sec: 10
    policies:
      - name: sample_10_percent
        type: probabilistic
        probabilistic:
          sampling_percentage: 10
service:
  pipelines:
    traces/1:
      receivers: [ otlp ]
      processors: [ elastictrace ]
      exporters: [ elasticapm, forward ]
    traces/2:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```
:::

## Configuration for a load-balancing Collector

All traces must go to the same collector in order for the sampling decision to be made. Therefore, when using a load-balancing collector with downstream collectors, the `traceID` should be set as the routing key in the load-balancing collector and tail-sampling should be applied in the downstream collectors.

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
processors:
  tail_sampling:
    decision_wait: 5s
    num_traces: 50000
    expected_new_traces_per_sec: 10
    policies:
      - name: sample_10_percent
        type: probabilistic
        probabilistic:
          sampling_percentage: 10
service:
  pipelines:
    traces/1:
      receivers: [ otlp ]
      processors: [ elastictrace ]
      exporters: [ elasticapm, forward ]
    traces/2:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```
:::
::::

## Resources

To learn more about tail-based sampling in the OpenTelemetry Collector, refer to the [Tail sampling OTel documentation](https://opentelemetry.io/docs/concepts/sampling/#tail-sampling).
