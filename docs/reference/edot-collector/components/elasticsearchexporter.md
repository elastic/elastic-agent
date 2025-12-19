---
navigation_title: Elasticsearch exporter
description: The Elasticsearch exporter is an OpenTelemetry Collector component that sends telemetry data to Elasticsearch.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector:
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Elasticsearch exporter

The {{es}} exporter is an OpenTelemetry Collector component that sends logs, metrics, and traces to {{es}}. The exporter supports multiple mapping modes and provides flexible configuration options for data routing, authentication, and performance tuning.

## Get started

To use the {{es}} exporter, include it in the exporter definitions of the [Collector configuration](/reference/edot-collector/config/index.md). The exporter is already included in the [default configuration](/reference/edot-collector/config/default-config-standalone.md).

## Configuration

The {{es}} exporter supports various configuration options for connecting to {{es}}, mapping data, and optimizing performance.

### Connection settings

You must specify exactly one of the following connection methods:

- `endpoint`: A single {{es}} URL. For example, `https://elasticsearch:9200`.
- `endpoints`: A list of {{es}} URLs for round-robin load balancing.
- `cloudid`: An [Elastic Cloud ID](docs-content://deploy-manage/deploy/elastic-cloud/find-cloud-id.md) for connecting to {{ecloud}}.

If none of the previous settings are specified, the exporter relies on the `ELASTICSEARCH_URL` environment variable.

### Authentication settings

The exporter supports standard OpenTelemetry [authentication configuration](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configauth/README.md#authentication-configuration). You can also use these simplified authentication options:

- `user` and `password`: For HTTP Basic Authentication
- `api_key`: For [{{es}} API key authentication](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key)

### TLS and security settings

The exporter supports standard OpenTelemetry TLS configuration for secure connections. You can configure TLS certificates, client authentication, and other security settings through the standard [TLS configuration options](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#tls-configuration-settings).

## Mapping modes

```{applies_to}
stack: ga 8.12
```

The exporter uses the `otel` mapping mode by default. In this mode, the {{es}} Exporter stores documents in Elastic's preferred OTel-native schema. Documents use the original attribute names and closely follow the event structure from the OTLP events.

:::{note}
The exporter supports other mapping modes (`ecs`, `bodymap`, `none`, `raw`) through the `mapping::mode` setting, but configuring these modes is not officially supported by the EDOT Collector. In a future release, the configuration option will be removed in favor of automatic mode selection.
:::

## Document routing

Documents are statically or dynamically routed to the target index or data stream. The first routing mode that applies is used, in the following order:

### Static mode

Static mode routes documents to `logs_index` for log records, `metrics_index` for data points, and `traces_index` for spans, if these configs aren't empty respectively.

### Dynamic mode (Index attribute)

Dynamic mode (Index attribute) routes documents to index name specified in `elasticsearch.index` attribute, with the following order of precedence: log record / data point / span attribute -> scope attribute -> resource attribute if the attribute exists.

### Dynamic mode (Data stream routing)

Dynamic mode (Data stream routing) routes documents to data stream constructed from `${data_stream.type}-${data_stream.dataset}-${data_stream.namespace}`,
where `data_stream.type` is `logs` for log records, `metrics` for data points, and `traces` for spans, and is static. The following rules apply:

- `data_stream.dataset` or `data_stream.namespace` in attributes, with the following order of precedence: log record / data point / span attribute -> scope attribute -> resource attribute
- Otherwise, if the scope name matches the `/receiver/(\w*receiver)` regular expression, `data_stream.dataset` is the first capture group.
- Otherwise, `data_stream.dataset` falls back to `generic` and `data_stream.namespace` falls back to `default`.

If the mapping mode is set to `bodymap`, the `data_stream.type` field can be dynamically set from attributes. The resulting documents contain the corresponding `data_stream.*` fields. Refer to [Data Stream Fields](ecs://reference/ecs-data_stream.md) for the restrictions applied to the data stream fields.

### Document routing settings

These settings allow you to customize document routing:

| Setting | Default | Description |
|---------|---------|-------------|
| `logs_index` | - | The index or data stream name to publish logs (and span events in OTel mapping mode) to. Should be empty unless all logs are to be sent to the same index. |
| `metrics_index` | - | The index or data stream name to publish metrics to. Should be empty unless all metrics should be sent to the same index. |
| `traces_index` | - | The index or data stream name to publish traces to. Should be empty unless all traces should be sent to the same index. |
| `logstash_format::enabled` | `false` | Turns on or off Logstash format compatibility. When active, the index name is composed using the dynamic routing rules as prefix and the date as suffix. For example, `logs-generic-default-YYYY.MM.DD`. |
| `logstash_format::prefix_separator` | `-` | Set a separator between logstash prefix and date. |
| `logstash_format::date_format` | `%Y.%m.%d` | Time format based on strftime to generate the second part of the index name. |
| `logs_dynamic_id::enabled` | `false` | Turns on or off dynamic ID for log records. If `elasticsearch.document_id` exists and isn't empty in log record attributes, it's used as the document ID. Otherwise, {{es}} generates the ID. The attribute is removed from the final document when using `otel` mapping mode. |

### Document routing exceptions

When using the default OpenTelemetry mapping mode, additional handling is applied to the previous document routing rules:

1. Static mode: Span events are separate documents routed to `logs_index` if non-empty.
2. Dynamic - Index attribute mode: Span events are separate documents routed using attribute `elasticsearch.index`, with the following order of precedence: span event attribute -> scope attribute -> resource attribute if the attribute exists.
3. Dynamic - Data stream routing mode: For all documents, `data_stream.dataset` always ends with `.otel`. Span events are separate documents that have `data_stream.type: logs` and are routed using data stream attributes, with the following order of precedence: span event attribute -> scope attribute -> resource attribute.

The `elasticsearch.index` attribute is removed from the final document if it exists.

## Performance and batching

### Using sending queue

The {{es}} exporter supports the `sending_queue` setting, which supports both queueing and batching.  The sending queue is deactivated by default.

You can turn on the sending queue by setting `sending_queue::enabled` to `true`:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    sending_queue:
      enabled: true
```

### Internal batching (default)

By default, the exporter performs its own buffering and batching, as configured through the `flush` setting, unless the `sending_queue::batch` or the `batcher` settings are defined. In that case, batching is controlled by either of the two settings, depending on the version.

### Custom batching

::::{applies-switch}

:::{applies-item} stack: ga 9.2
Batching support in sending queue is deactivated by default. To turn it on, enable sending queue and define `sending_queue::batch`. 

For example:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    sending_queue:
      enabled: true
      batch:
        min_size: 1000
        max_size: 10000
        timeout: 5s
```
:::

:::{applies-item} stack: ga 9.0, deprecated 9.2

Batching can be enabled and configured with the `batcher` section, using [common `batcher` settings](https://github.com/open-telemetry/opentelemetry-collector/blob/main/exporter/exporterhelper/internal/queue_sender.go).

- `batcher`:
  - `enabled` (default=unset): Enable batching of requests into 1 or more bulk requests. On a batcher flush, it is possible for a batched request to be translated to more than 1 bulk request due to `flush::bytes`.
  - `sizer` (default=items): Unit of `min_size` and `max_size`. Currently supports only "items", in the future will also support "bytes".
  - `min_size` (default=5000): Minimum batch size to be exported to {{es}}, measured in units according to `batcher::sizer`.
  - `max_size` (default=0): Maximum batch size to be exported to {{es}}, measured in units according to `batcher::sizer`. To limit bulk request size, configure `flush::bytes` instead. :warning: It is recommended to keep `max_size` as 0 as a non-zero value may lead to broken metrics grouping and indexing rejections.
  - `flush_timeout` (default=10s): Maximum time of the oldest item spent inside the batcher buffer, aka "max age of batcher buffer". A batcher flush will happen regardless of the size of content in batcher buffer.

For example:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    batcher:
      enabled: true
      min_size: 1000
      max_size: 10000
      flush_timeout: 5s
```
:::
::::

## Bulk indexing

The {{es}} exporter uses the [{{es}} Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk) for indexing documents. Configure the behavior of bulk indexing with the following settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `num_workers` | `runtime.NumCPU()` | Number of workers publishing bulk requests concurrently. Note this isn't applicable if `batcher::enabled` is `true` or `false`. |
| `flush::bytes` | `5000000` | Write buffer flush size limit before compression. A bulk request are sent immediately when its buffer exceeds this limit. This value should be much lower than Elasticsearch's `http.max_content_length` config to avoid HTTP 413 Entity Too Large error. Keep this value under 5 MB. |
| `flush::interval` | `10s` | Write buffer flush time limit. |
| `retry::enabled` | `true` | Turns on or off request retry on error. Failed requests are retried with exponential backoff. |
| `retry::max_requests` | DEPRECATED | Number of HTTP request retries including the initial attempt. If used, `retry::max_retries` is set to `max_requests - 1`. Use `retry::max_retries` instead. |
| `retry::max_retries` | `2` | Number of HTTP request retries. To turn off retries, set `retry::enabled` to `false` instead of setting `max_retries` to `0`. |
| `retry::initial_interval` | `100ms` | Initial waiting time if an HTTP request failed. |
| `retry::max_interval` | `1m` | Max waiting time if an HTTP request failed. |
| `retry::retry_on_status` | `[429]` | Status codes that trigger request or document level retries. Request level retry and document level retry status codes are shared and cannot be configured separately. To avoid duplicates, it defaults to `[429]`. |

:::{note}
The `flush::interval` config is ignored when `batcher::enabled` config is explicitly set to true or false.
:::

Starting from {{es}} 8.18 and higher, the [`include_source_on_error`](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk#operation-bulk-include_source_on_error) query parameter allows users to receive the source document in the error response if there were parsing errors in the bulk request. In the exporter, the equivalent configuration is also named `include_source_on_error`.

- `include_source_on_error`:
  - `true`: Turns on bulk index responses to include source document on error. {applies_to}`stack: ga 8.18`
  - `false`: Turns off including source document on bulk index error responses. {applies_to}`stack: ga 8.18`
  - `null` (default): Backward-compatible option for older {{es}} versions. By default, the error reason is discarded from bulk index responses entirely. Only the error type is returned.

:::{warning}
The exporter might log error responses containing request payload, causing potential sensitive data to be exposed in logs.
:::

## Ingest pipeline support

Documents can be passed through an [{{es}} Ingest pipeline] before indexing. Use these settings to configure the ingest pipeline:

| Setting | Default | Description |
|---------|---------|-------------|
| `pipeline` | - | ID of an {{es}} Ingest pipeline used for processing documents published by the exporter. |
| `logs_dynamic_pipeline::enabled` | `false` | Turn on or off the dynamic pipeline. If `elasticsearch.ingest_pipeline` attribute exists in log record attributes and isn't empty, it's used as the {{es}} ingest pipeline. This currently only applies to the log signal. The attribute is removed from the final document when using `otel` mapping mode. |

For example:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    pipeline: "my-custom-pipeline"
```

## {{es}} node discovery

The {{es}} Exporter regularly checks {{es}} for available nodes. Newly discovered nodes are automatically used for load balancing. 

The following settings are related to node discovery:

- `discover`:
  - `on_start` (optional): If enabled the exporter queries {{es}}
    for all known nodes in the cluster on startup.
  - `interval` (optional): Interval to update the list of {{es}} nodes.

To turn off node discovery, set `discover.interval` to `0`.

## Known limitations

The following are some known limitations of the {{es}} exporter:

- Metrics support is currently in development and might have limitations.
- Profile support requires Universal Profiling to be installed in {{es}}.
- Some mapping modes might have reduced functionality for certain telemetry types.
- The `bodymap` mode only supports logs and ignores other telemetry types.


## Known issues

The following are the main known issues with the {{es}} exporter:

| Issue | Cause | Solution |
|-------|-------|----------|
| **version_conflict_engine_exception** | TSDB data streams require unique documents per timestamp. Occurs with OTel mapping mode on {{es}} 8.16+ or ECS mode with system integration streams. | Update to {{es}} version 8.17.6 or higher and the {{es}} exporter version 0.121.0 or higher, or install a custom component template. Remove batch processors to prevent metric splitting. |
| **flush failed (400) illegal_argument_exception** | OTel mapping mode, which is default from version 0.122.0, requires {{es}} 8.12 or higher. | Upgrade {{es}} to 8.12 or higher or use alternative mapping modes. |

## Troubleshooting

When you encounter issues with the {{es}} exporter, you can try the following:

- Make sure your {{es}} version is compatible with your chosen mapping mode.
- Verify your API keys or credentials are valid and have appropriate permissions.
- Check that your {{es}} cluster supports the required features for your mapping mode.
