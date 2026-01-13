---
navigation_title: Prometheus remote Write receiver
description: The Prometheus remote write receiver is an OpenTelemetry Collector component that receives metrics from Prometheus using the remote write protocol.
applies_to:
  stack: ga 9.3
  serverless:
    observability:
  product:
    edot_collector: ga 9.3
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# Prometheus remote write receiver

The Prometheus remote write receiver gets metrics from Prometheus instances using the [Prometheus remote write 2.0 protocol](https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/). This receiver allows you to forward Prometheus metrics to the OpenTelemetry Collector for processing and exporting to {{es}} or other destinations.

## Get started

To use the Prometheus remote write receiver, include it in the receiver definitions of the [Collector configuration](/reference/edot-collector/config/index.md):

```yaml
receivers:
  prometheusremotewrite:
    endpoint: 0.0.0.0:9090
```

You must also configure Prometheus to send metrics using the remote write 2.0 protocol. Refer to [Configure your Prometheus instance](#configure-your-prometheus-instance) for details.

## Configuration

The receiver configuration is based on the standard [OpenTelemetry HTTP server configuration](https://github.com/open-telemetry/opentelemetry-collector/tree/main/config/confighttp). The main option is:

| Option | Description |
|--------|-------------|
| `endpoint` | The address and port to listen on for incoming remote write requests. |

For the full list of HTTP server options, refer to the [confighttp documentation](https://github.com/open-telemetry/opentelemetry-collector/tree/main/config/confighttp).

## Configure your Prometheus instance

To send metrics from Prometheus to this receiver, configure Prometheus with the following settings.

### Enable metadata write-ahead log records

Prometheus remote write relies on write-ahead log (WAL) records. By default, metadata information, such as metric type, unit, and help description, are not appended to the WAL. Because this information is required to translate remote write data into OTLP, turn on the `metadata-wal-records` feature flag when starting Prometheus:

```console
./prometheus --config.file config.yml --enable-feature=metadata-wal-records
```

### Configure remote write 2.0

This receiver only supports the [Prometheus remote write v2 protocol](https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/). Configure your Prometheus `remote_write` block to use the v2 protocol:

```yaml
remote_write:
  - url: "http://<collector-host>:9090/api/v1/write"
    protobuf_message: io.prometheus.write.v2.Request
```

Replace `<collector-host>` with the address where your EDOT Collector is running.

For more details on configuring Prometheus, refer to the [upstream receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusremotewritereceiver#configuring-your-prometheus).

## Prometheus version compatibility

The remote write 2.0 protocol specification is still evolving, and compatibility depends on matching versions:

| OTel Collector Contrib Version | Compatible Prometheus Versions |
|-------------------------------|-------------------------------|
| v0.141.0 and earlier | Prometheus 3.7.x and earlier |
| v0.142.0 and later | Prometheus 3.8.0 and later |

:::{important}
EDOT Collector uses `prometheusremotewritereceiver` v0.141.0 and later, which is compatible with Prometheus 3.7.x and earlier. If you're using Prometheus 3.8.0 or later, you might experience compatibility issues due to breaking changes in the remote write 2.0 protocol.
:::

## Limitations

The Prometheus remote write receiver has some behaviors to be aware of:

* **Summaries and Classic Histograms are unsupported.** Classic Histograms and Summaries are composed of multiple separate time series, which can be sent in separate Remote Write requests. This makes it impossible to determine if all parts have been received. Use Prometheus Native Histograms instead.

* **Resource metrics cache.** The receiver uses an internal LRU cache to store `target_info` metrics across requests. The cache has a hardcoded limit of 1,000 resource metrics. If the process restarts, the cache is lost, which might cause some inconsistencies.

* **Remote write v1 is not supported.** The receiver only supports the remote write 2.0 protocol. Remote write v1 lacks support for metadata, created timestamps, and atomic histogram ingestion.


## Resources

* [Upstream component: prometheusremotewritereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/prometheusremotewritereceiver/README.md)
* [Prometheus Remote Write 2.0 specification](https://prometheus.io/docs/specs/prw/remote_write_spec_2_0/)
* [Configure metrics collection in EDOT](../config/configure-metrics-collection.md)

