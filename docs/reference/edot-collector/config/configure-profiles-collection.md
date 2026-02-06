---
navigation_title: Profiles collection
description: Learn how to configure and customize profiles collection through the Elastic Distribution of OpenTelemetry Collector.
applies_to:
  stack: preview 9.2+
  serverless:
    observability: preview
  product:
    edot_collector: preview 9.2+
products:
  - id: observability
  - id: edot-collector
---

# Configure profiles collection

The {{edot}} (EDOT) Collector includes a profiling receiver, which offers an eBPF-based, system-wide profiler.

To activate and configure profiling and send profiles to {{ecloud}} or {{es}}, follow these instructions.

:::{important}
OpenTelemetry profiling is still under active development. Refer to [The State of Profiling](https://opentelemetry.io/blog/2024/state-profiling/) blog post for more information.
:::

## Turn on profiling

Follow these steps to turn on profiles collection through the EDOT Collector.

:::::{stepper}
::::{step} Activate profiling in the Collector
To activate profiling in the EDOT Collector, start it using the additional argument `--feature-gates=service.profilesSupport`.

For example:

```sh
sudo ./otelcol --config otel.yml --feature-gates=service.profilesSupport
```
::::
:::::

## System requirements

The profiling receiver is only available on Linux. Running it on an operating system other than Linux results in an error.

The supported Linux kernel versions are either 5.4 and later for x86_64 or 5.5 and later for ARM64.

## Supported runtimes

The profiling receiver handles native runtimes, like C, C++, Go and Rust, as well as various interpreters.

The minimum supported versions of each interpreter are:

- JVM/JDK: 7
- Python: 3.6
- V8: 8.1.0
- Perl: 5.28
- PHP: 7.3
- Ruby: 2.5
- .Net: 6
- Erlang/OTP 27.2.4 

## Generate metrics from profiles

You can configure the components to generate and report metrics exclusively from profile information. This method contributes to a reduction in ingest traffic and storage costs.

The following example generates profiling metrics by frame, frame type, and classification:

::::{applies-switch}

:::{applies-item} stack: preview =9.2
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
:::

:::{applies-item} stack: preview 9.3+
```yaml
connectors:
  profilingmetrics:

receivers:
  profiling:

service:
  pipelines:
    profiles:
      receivers: [ profiling ]
      exporters: [ profilingmetrics ]
    metrics:
      receivers: [ profilingmetrics ]
      exporters: [ elasticsearch ]
```
:::

::::

## Kubernetes deployments

In Kubernetes, we suggest deploying the EDOT Collector with a profiling receiver as a DaemonSet. This ensures comprehensive, node-level profiling across the entire cluster, providing consistent data collection, resilience, scalability, and simplified management. This approach is recommended for optimal performance and full observability.
