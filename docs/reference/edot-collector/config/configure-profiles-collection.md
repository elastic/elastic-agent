---
navigation_title: Profiles collection
description: Configure the EDOT Collector for profiles collection.
applies_to:
  stack: preview 9.2
  serverless:
    observability:
  product:
    edot_collector: preview
products:
  - id: observability
  - id: edot-collector
---

# Profiles support in EDOT

Profiles represent the fourth pillar of observability, complementing logs, traces, and metrics.

The Elastic Distributions of OpenTelemetry (EDOT) Collector includes a profiling receiver, which offers an eBPF-based, system-wide profiler.

Deploying the EDOT Collector with a profiling receiver in Kubernetes should be done as a DaemonSet. This ensures comprehensive, node-level profiling across the entire complete cluster, providing consistent data collection, resilience, scalability, and simplified management. This approach is recommended for optimal performance and complete observability.

::{note}
OpenTelemetry profiles is not yet a stable feature. To use it, Elastic Distributions
of OpenTelemetry (EDOT) Collector need to be started with the additional argument `--feature-gates=service.profilesSupport`.
::

## Full profiles collection

For full profiles collection and reporting use the following configuration.

::{note}
Please follow the steps in Kibana to [`set up Universal Profiling`] before applying the following configuration.
::

```yaml
receivers:
  profiling:
    SamplesPerSecond: 19

service:
  pipelines:
    profiles:
      receivers: [ profiling ]
      exporters: [ elasticsearch ]
```

## Generate metrics from profiles

The system can be configured to generate and report metrics exclusively from profile information. This method contributes to a reduction in ingest traffic and storage costs.

```yaml
connectors:
  profilingmetrics:
    by_frame: true
    by_frametype: true
    by_classification: true

receivers:
  profiling:
    SamplesPerSecond: 19

service:
  pipelines:
    profiles:
      receivers: [ profiling ]
      exporters: [ profilingmetrics ]
    metrics:
      receivers: [ profilingmetrics ]
      exporters: [ elasticsearch ]
```

[`set up Universal Profiling`]: https://www.elastic.co/docs/solutions/observability/infra-and-hosts/get-started-with-universal-profiling#profiling-configure-data-ingestion 