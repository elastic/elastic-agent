### elasticmonitoringreceiver

> **NOTE**: This component is for **internal use only**. Its behavior and exposed metrics may change without notice, and backward compatibility is not guaranteed.

Standalone beats expose telemetry data via the [stats endpoint](https://www.elastic.co/guide/en/beats/filebeat/current/http-endpoint.html#_stats). When running beats as receivers in the OpenTelemetry collector, this telemetry data is partially available, computed from otel and exporter components and ingested via the `elasticmonitoringreceiver`.

```yaml
receivers:
  elasticmonitoringreceiver:
    interval: 60s
exporters:
  elasticsearch/1:
// ...
service:
  pipelines:
    logs:
      receivers: [elasticmonitoringreceiver]
      exporters:
        - elasticsearch/1
```

> In order to fetch exporter metrics, the `telemetry.newPipelineTelemetry` feature gate should be enabled.

Receiver events are generated per exporter and follow the format below:

```json
{"beat":{"stats":{"libbeat":{"output":{"events":{"batches":10,"acked":4,"dropped":2,"total":6,"active":0,"failed":4},"write":{"bytes":1968}},"pipeline":{"queue":{"max_events":3200,"filled":{"events":0,"pct":0.0}}}}}},"component":{"id":"elasticsearch/1"},"@timestamp":"2026-01-21T12:13:00.546Z"}
```

Here is a list of metrics currently available when using the `elasticmonitoringreceiver`. Note that their semantics may differ from those in standalone Beats, as they are derived from a set of [internal collector metrics](https://opentelemetry.io/docs/collector/internal-telemetry/) and [internal elasticsearchexporter metrics](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/elasticsearchexporter/documentation.md#internal-telemetry) to fit the Beat metrics model as closely as possible.

- `beat.stats.libbeat.pipeline.queue.filled.events`: otelcol_exporter_queue_size
- `beat.stats.libbeat.pipeline.queue.max_events`: otelcol_exporter_queue_capacity
- `beat.stats.libbeat.pipeline.queue.filled.pct`: derived from queue size / capacity
- `beat.stats.libbeat.output.events.total`: otelcol.elasticsearch.docs.processed
- `beat.stats.libbeat.output.events.active`: otelcol.elasticsearch.docs.processed - (otelcol_exporter_send_failed_log_records + otelcol_exporter_send_failed_spans + otelcol_exporter_send_failed_metric_points)
- `beat.stats.libbeat.output.events.acked`: otelcol_exporter_sent_metric_points + otelcol_exporter_sent_spans + otelcol_exporter_sent_log_records
- `beat.stats.libbeat.output.events.dropped`: otelcol_exporter_send_failed_log_records + otelcol_exporter_send_failed_spans + otelcol_exporter_send_failed_metric_points
- `beat.stats.libbeat.output.events.failed`: otelcol.elasticsearch.docs.retried.
- `beat.stats.libbeat.output.events.batches`: otelcol.elasticsearch.bulk_requests.count
- `beat.stats.libbeat.output.write.bytes`: otelcol.elasticsearch.flushed.bytes
