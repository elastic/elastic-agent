---
navigation_title: Prometheus remote write v1 receiver
description: The Prometheus remote write v1 receiver is an OpenTelemetry Collector component that receives metrics from Prometheus using the remote write 1.0 protocol.
applies_to:
  stack: ga 9.5
  serverless:
    observability: ga
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# Prometheus remote write v1 receiver

The Prometheus remote write v1 receiver gets metrics from Prometheus and compatible agents using the [Prometheus remote write 1.0 protocol](https://prometheus.io/docs/specs/prw/remote_write_spec/). It accepts writes on an HTTP endpoint and translates them into OpenTelemetry metrics.

Use this receiver when the sender speaks remote write 1.0. For remote write 2.0, use the [Prometheus remote write receiver](/reference/edot-collector/components/prometheusremotewritereceiver.md).

## Get started

Include the receiver in the [Collector configuration](/reference/edot-collector/config/index.md):

```yaml
receivers:
  prometheusremotewritev1:
    endpoint: 0.0.0.0:9090
```

Point Prometheus `remote_write` at the receiver:

```yaml
remote_write:
  - url: "http://<collector-host>:9090/api/v1/write"
```

Replace `<collector-host>` with the address where the EDOT Collector is running.

## Configuration

The receiver configuration is the standard [OpenTelemetry HTTP server configuration](https://github.com/open-telemetry/opentelemetry-collector/tree/main/config/confighttp).

| Option | Description |
|--------|-------------|
| `endpoint` | Address and port to listen on for incoming remote write requests. The default is `localhost:9090`. |

The receiver serves `POST /api/v1/write` and expects `Content-Type: application/x-protobuf`.

## Limitations

Each time series becomes one gauge metric. Labels other than `__name__` are stored as data point attributes. The receiver does not set resource attributes and does not preserve Prometheus metric type, unit, or help text from remote write 1.0 metadata.

## Resources

* [Elastic component: prometheusremotewritev1receiver](https://github.com/elastic/opentelemetry-collector-components/tree/main/receiver/prometheusremotewritev1receiver)
* [Prometheus Remote Write 1.0 specification](https://prometheus.io/docs/specs/prw/remote_write_spec/)
* [Configure metrics collection in EDOT](../config/configure-metrics-collection.md)
