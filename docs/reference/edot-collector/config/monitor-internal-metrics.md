---
navigation_title: Monitor internal metrics
description: Monitor the health and performance of the EDOT Collector using its internal OpenTelemetry metrics.
applies_to:
  product:
    edot_collector: ga
---

# Monitor the EDOT Collector with internal metrics

The EDOT Collector exposes internal OpenTelemetry metrics that provide visibility into its health, performance, and telemetry pipeline behavior. Monitoring these metrics can help you proactively detect backpressure, exporter failures, dropped spans, and resource saturation before they impact data ingestion.

## Enable internal metrics

The EDOT Collector exposes internal metrics in Prometheus format by default at `http://127.0.0.1:8888/metrics`. To expose metrics on all interfaces or customize the endpoint, update the `service.telemetry.metrics` section in your Collector configuration.

### Expose metrics for scraping

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

This configuration serves metrics on port 8888 and makes them available to scrape from any network interface.

:::{note}
The exact configuration might vary based on deployment mode and whether metrics are scraped directly or forwarded by another collector or {{agent}}.
:::

## Collect internal metrics

To collect internal metrics, use the EDOT Collector's Prometheus receiver (`prometheusreceiver`) to scrape the Prometheus endpoint exposed by the Collector. Unlike the metricbeat-style `prometheus/metrics` input, this contrib, OTLP-native receiver doesn't add ECS fields as metadata.

### Scrape internal metrics with the Prometheus receiver

When running the Collector (including under {{agent}}), add a Prometheus receiver and a metrics pipeline that scrapes the internal metrics endpoint. For example:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: 'otelcol-internal'
          static_configs:
            - targets: ['127.0.0.1:8888']
          metrics_path: /metrics

service:
  pipelines:
    metrics/internal:
      receivers:
        - prometheus
      exporters:
        - otlp
```

Replace `127.0.0.1:8888` with `<collector-host>:8888` if scraping from another host. After ingestion, these metrics are available in {{product.observability}} for dashboards, visualizations, and alerting.

## Key metrics to monitor

The EDOT Collector emits internal metrics under the `otelcol.*` namespace (refer to the [Collector service metadata](https://github.com/open-telemetry/opentelemetry-collector/blob/main/service/metadata.yaml) for more information). However, when you scrape the Prometheus endpoint, metric names are normalized to Prometheus format and appear with the `otelcol_*` prefix (dots become underscores). Use them to monitor the Collector’s internal state and surface operational issues.

### Pipeline throughput

Monitor telemetry flow across pipeline stages:

- `otelcol_receiver_accepted_spans`  
- `otelcol_receiver_refused_spans`  
- `otelcol_receiver_failed_spans`  
- `otelcol_exporter_sent_spans`  
- `otelcol_exporter_send_failed_spans`

Look for gaps between accepted and sent spans to identify delays or failures.

### Queue and backpressure

Monitor queue pressure between processors and exporters:

- `otelcol_exporter_queue_size`  
- `otelcol_exporter_queue_capacity`  
- `otelcol_exporter_enqueue_failed_spans`

Rising queue sizes or enqueue failures might signal backpressure or telemetry loss.

### Exporter failures and retries

Track send failures and retry behavior:

- `otelcol_exporter_send_failed_spans`  
- `otelcol_exporter_send_failed_metric_points`  
- `otelcol_exporter_send_failed_log_records`

High failure counts might result from network errors, invalid credentials, or backend throttling. Exporters might retry failed sends automatically, so these metrics don't always indicate data loss.

### Resource usage

Monitor the Collector's resource utilization:

- `otelcol_process_memory_rss`  
- `otelcol_process_cpu_seconds`  
- `otelcol_runtime_num_goroutines`

High or growing values can indicate memory leaks, inefficient configuration, or excessive load.

## Detect and respond to common issues

The following patterns help identify and resolve common Collector performance issues.

### Growing queues and dropped telemetry

Symptoms:
- Queue size increases over time  
- Enqueue failures or dropped spans

Causes:
- Backend slowness or outages  
- Exporter throughput limits  
- Insufficient Collector resources

Resolution:
- Check exporter health and credentials  
- Tune queue and batch settings  
- Scale the Collector instance or deployment

For more information, refer to [Export failures when sending telemetry data](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/trace-export-errors.md) (`sending_queue` overflow, exporter timeouts), [429 errors when using the mOTLP endpoint](docs-content://troubleshoot/ingest/opentelemetry/429-errors-motlp.md) (rate limiting and backpressure).

### High exporter failure rates

Symptoms:
- Elevated `*_send_failed_*` metrics  
- Growing retry queues

Causes:
- Network issues or timeouts  
- Backend rate limiting  
- Misconfigured authentication

Resolution:
- Verify backend availability and credentials  
- Review ingestion limits and retry logic  
- Investigate latency or firewall constraints

For more information, refer to [Export failures when sending telemetry data](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/trace-export-errors.md) (export failures, retries), [429 errors when using the mOTLP endpoint](docs-content://troubleshoot/ingest/opentelemetry/429-errors-motlp.md) (rate limiting), [Connectivity issues with EDOT](docs-content://troubleshoot/ingest/opentelemetry/connectivity.md) (network, authorization, firewall).

### Excessive memory or CPU usage

Symptoms:
- Rising memory RSS  
- Sustained high CPU usage
- Increasing goroutine count

Causes:
- High-volume telemetry ingestion  
- Inefficient processor configurations  
- Memory leaks in custom components

Resolution:
- Adjust sampling or processing logic  
- Increase resource limits  
- Horizontally scale Collector instances

For more information, refer to [Collector out of memory](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/collector-oomkilled.md) (OOM errors, memory exhaustion), [Insufficient resources in Kubernetes](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/insufficient-resources-kubestack.md) (resource limits, scaling).

## Dashboards and alerting

Use internal metrics to create dashboards and alerting rules. Track real-time pipeline health and detect regressions early.

Example alert scenarios:

- Exporter queue usage exceeds 80% for more than 5 minutes  
- Send failure rate exceeds a defined threshold  
- Dropped spans exceed a historical baseline  

## Resources

- [Contrib OpenTelemetry Collector internal telemetry documentation](https://opentelemetry.io/docs/collector/internal-telemetry/)
- [Contrib OpenTelemetry metrics reference](https://opentelemetry.io/docs/specs/otel/metrics/)
- [EDOT Collector configuration reference](/reference/edot-collector/config/index.md)
- [EDOT Collector troubleshooting](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/index.md)