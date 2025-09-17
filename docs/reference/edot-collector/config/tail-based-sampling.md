---
navigation_title: Tail-based Sampling
description: Configuration of the EDOT Collector for Tail-based sampling.
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

# Configure tail-based sampling

Tail-based sampling is where the decision to sample a trace takes place by considering all or most of the spans within the trace. This is in contrast to Head-based sampling, which is on the client-side where traces are created.

Because metrics are calculated and aggregations are performed on trace data in the EDOT collector, some specific configuration is required to ensure that the tail sampling decisions are made after these calculations.
Otherwise, the metrics and aggregations would be incorrect due to the partial representation of traces.

Enforcing a specific order of calculations and sampling decisions can be accomplished in the EDOT Collector using the [forward connector](https://github.com/open-telemetry/opentelemetry-collector/tree/main/connector/forwardconnector). The traces pipeline should be split into two parts using the forward connector, with the first part applying calculations and the second part applying the tail-based sampling decision.

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
      receivers: [otlp]
      processors: [elastictrace]
      exporters: [ elasticapm, forward ]
    traces/2:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```
:::

## Configure a load-balancing EDOT Collector with downstream collectors

All traces must go to the same collector in order for the sampling decision to be made. Therefore, when using a load-balancing collector with downstream collectors, the `traceID` should be set as the routing key in the load-balancing collector and tail-sampling should be applied in the downstream collectors.

:::{tab-item} Load-balancing EDOT Collector config
```yaml
exporters:
  loadbalancing:
    routing_key: traceID
```
:::

:::{tab-item} Downstream EDOT Collector config
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
      receivers: [otlp]
      processors: [elastictrace]
      exporters: [ elasticapm, forward ]
    traces/2:
      receivers: [ forward ]
      processors: [ tail_sampling ]
      exporters: [ elasticsearch/otel ]
```
:::

## Resources

[Tail sampling OTel documentation](https://opentelemetry.io/docs/concepts/sampling/#tail-sampling)
