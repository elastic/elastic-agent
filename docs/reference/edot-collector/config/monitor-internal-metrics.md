---
navigation_title: Monitor EDOT Collector internal metrics
description: Monitor the health and performance of the EDOT Collector using its internal OpenTelemetry metrics.
applies_to:
  product:
    edot_collector: ga
---

# Monitor the EDOT Collector with internal metrics

The EDOT Collector exposes internal OpenTelemetry metrics that offer visibility into its health, performance, and data flow. Monitoring these metrics helps you detect problems with backpressure, exporter failures, dropped telemetry, and resource saturation before they impact your observability pipeline.

This guide explains how to enable and collect internal metrics from the Collector, highlights key `otelcol_*` metrics to monitor, and shows how to use them for alerting and using dashboards.


## Overview

The EDOT Collector publishes internal metrics that describe:

- Telemetry throughput across receivers, processors, and exporters  
- Queue usage and backpressure  
- Exporter failures and retries  
- Resource usage, including memory 

These metrics use the `otelcol_*` namespace and are emitted by the Collector itself. You can use them to monitor the Collector's health, detect dropped or delayed telemetry, identify pipeline bottlenecks, and power alerts and dashboards for proactive operations.

## Build dashboards and alerts

You can use internal metrics to build dashboards and alerting rules for queue usage nearing capacity, exporter failure or retry rates above thresholds, sudden drops in telemetry throughput, or sustained resource saturation.  

### Alert examples

You can configure alerts to:

- Trigger when exporter queue usage exceeds 80% for 5+ minutes  
- Alert on send failure rates above a defined threshold  
- Notify when dropped spans exceed baseline levels  


## Enable internal metrics in the EDOT Collector

By default, the EDOT Collector exposes its internal metrics using a Prometheus endpoint at `http://127.0.0.1:8888/metrics`. To expose the endpoint on all network interfaces or customize the configuration, use the `service.telemetry.metrics` section in your Collector configuration.

### Example configuration

```yaml
service:
  telemetry:
    metrics:
      readers:
        - pull:
            exporter:
              prometheus:
                host: '0.0.0.0'
                port: 8888
```

This configuration exposes internal metrics on port 8888 in Prometheus format, accessible on all network interfaces.

:::{note}
The exact configuration might vary based on your deployment mode and whether metrics are scraped directly or forwarded through another collector or {{agent}}.
:::

## Collect internal metrics with {{agent}}

You can collect internal metrics using {{agent}} by scraping the Prometheus endpoint exposed by the Collector.

### Example {{agent}} configuration

```yaml
inputs:
  - type: prometheus/metrics
    hosts:
      - http://<collector-host>:8888/metrics
    metrics_path: /metrics
```

When they are ingested, these metrics are available in {{product.observability}} for dashboards and alerting.


## Key `otelcol_*` metrics to monitor

The following sections describe the most important `otelcol_*` metrics organized by category. Use these metrics to monitor the Collector's performance and identify potential issues in your observability pipeline.

### Pipeline throughput

- `otelcol_receiver_accepted_spans`  
- `otelcol_receiver_refused_spans`  
- `otelcol_exporter_sent_spans`  
- `otelcol_exporter_send_failed_spans`  

Use these metrics to verify end-to-end telemetry flow. A widening gap between accepted and sent spans may indicate backpressure or exporter issues.

### Queue and backpressure

- `otelcol_exporter_queue_size`  
- `otelcol_exporter_queue_capacity`  
- `otelcol_exporter_enqueue_failed_spans`  

Monitor these to detect congestion between processors and exporters. High queue usage or increasing enqueue failures may result in dropped telemetry.

### Exporter failures and retries

- `otelcol_exporter_send_failed_spans`  
- `otelcol_exporter_send_failed_metric_points`  
- `otelcol_exporter_send_failed_log_records`  

High failure rates often signal network issues, authentication errors, or backend throttling. Note that these metrics don't inherently imply data loss since exporters may retry failed sends.

### Resource usage

- `otelcol_process_memory_rss`  
- `otelcol_process_cpu_seconds`  
- `otelcol_runtime_num_goroutines`  

Use these to detect memory leaks, CPU saturation, or excessive goroutine counts.


## Interpret common patterns

The following sections describe common patterns you might observe in your Collector metrics and how to interpret them. Each pattern includes symptoms, possible causes, and recommended actions to help you diagnose and resolve issues.

### Increasing queue size and dropped telemetry

Symptoms:

- Steadily growing queue size  
- Rising enqueue failures or dropped spans  

Possible causes:

- Backend latency or downtime  
- Exporter throughput limitations  
- Insufficient collector resources  

Resolution:

- Verify exporter connectivity and credentials  
- Increase queue capacity or batch size  
- Scale the collector horizontally or vertically  


### High exporter failure rates

Symptoms:

- Rising `*_send_failed_*` metrics  
- Growing retry queues  

Possible causes:

- Network or connectivity issues  
- Backend throttling  
- Invalid or expired credentials  

Resolution:

- Check backend availability and credentials  
- Investigate network latency or firewall issues  
- Review backend ingestion limits  


### High memory or CPU usage

Symptoms:

- Rapid RSS memory growth  
- Sustained high CPU usage  
- Rising goroutine count  

Possible causes:

- Excessive telemetry volume  
- Inefficient processor configurations  
- Memory leaks in custom components  

Resolution:

- Review sampling and processing configuration  
- Increase resource limits  
- Scale the collector deployment  


## Resources

- [Contrib OpenTelemetry Collector internal telemetry documentation](https://opentelemetry.io/docs/collector/internal-telemetry/)
- [Contrib OpenTelemetry metrics reference](https://opentelemetry.io/docs/specs/otel/metrics/)
- [EDOT Collector configuration reference](/reference/edot-collector/config/index.md)
- [EDOT Collector troubleshooting guides](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/index.md)