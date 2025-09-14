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

The Elasticsearch exporter is an OpenTelemetry Collector component that sends logs, metrics, and traces to {{es}}. The exporter supports multiple mapping modes and provides flexible configuration options for data routing, authentication, and performance tuning.

## Get started

To use the Elasticsearch exporter, include it in the exporter definitions of the [Collector configuration](/reference/edot-collector/config/index.md). The exporter is already included in the [default configuration](/reference/edot-collector/config/default-config-standalone.md).

## Configuration

The Elasticsearch exporter supports various configuration options for connecting to Elasticsearch, mapping data, and optimizing performance.

### Connection settings

You must specify exactly one of the following connection methods:

- `endpoint`: A single Elasticsearch URL. For example, `https://elasticsearch:9200`.
- `endpoints`: A list of Elasticsearch URLs for round-robin load balancing.
- `cloudid`: An [Elastic Cloud ID](docs-content://deploy-manage/deploy/elastic-cloud/find-cloud-id.md) for connecting to {{ecloud}}.

If none of the previous settings are specified, the exporter relies on the `ELASTICSEARCH_URL` environment variable.

### Authentication settings

The exporter supports standard OpenTelemetry [authentication configuration](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configauth/README.md#authentication-configuration). You can also use these simplified authentication options:

- `user` and `password`: For HTTP Basic Authentication
- `api_key`: For [Elasticsearch API key authentication](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key)

### TLS and security settings

The exporter supports standard OpenTelemetry TLS configuration for secure connections. You can configure TLS certificates, client authentication, and other security settings through the standard [TLS configuration options](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#tls-configuration-settings).

## Mapping modes

The exporter supports several mapping modes that determine how your telemetry data is preprocessed and stored in Elastic. You can configure the mapping mode through the `mapping` setting:

| Setting | Default | Description |
|---------|---------|-------------|
| `mapping::mode` | `otel` | The default mapping mode. Valid modes are: `none`, `ecs`, `otel`, `raw`, `bodymap`. |
| `mapping::allowed_modes` | All mapping modes | A list of allowed mapping modes that can be requested through client metadata or scope attributes. |

### OTel mapping mode

```{applies_to}
stack: ga 8.12
```

The default mapping mode is `otel`. In the `otel` mapping mode, the Elasticsearch Exporter stores documents in Elastic's preferred OTel-native schema. In this mapping mode, documents use the original attribute names and closely follow the event structure from the OTLP events.

### ECS mapping mode

In `ecs` mapping mode, the Elasticsearch Exporter maps fields from OpenTelemetry Semantic Conventions (SemConv) to Elastic Common Schema (ECS) where possible. This mode can be used for compatibility with existing dashboards that work with ECS. Refer to [ECS & OpenTelemetry](ecs://reference/ecs-opentelemetry.md) for more details.

### Bodymap mapping mode

In `bodymap` mapping mode, the Elasticsearch Exporter supports only logs and takes the body of a log record as the exact content of the Elasticsearch document without any transformation. Use this mapping mode when you want to have complete control over the Elasticsearch document structure.

### None mapping mode

In the `none` mapping mode the Elasticsearch Exporter produces documents with the original field names from the OTLP data structures.

### Raw mapping mode

The `raw` mapping mode is identical to `none`, except for two differences:

 - In `none` mode attributes are mapped with an `Attributes.` prefix, while in `raw` mode they are not.
 - In `none` mode span events are mapped with an `Events.` prefix, while in `raw` mode they are not.

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
| `logs_dynamic_id::enabled` | `false` | Turns on or off dynamic ID for log records. If `elasticsearch.document_id` exists and isn't empty in log record attributes, it's used as the document ID. Otherwise, Elasticsearch generates the ID. The attribute is removed from the final document when using `otel` mapping mode. |

### Document routing exceptions

When using the default OpenTelemetry mapping mode, additional handling is applied to the previous document routing rules:

1. Static mode: Span events are separate documents routed to `logs_index` if non-empty.
2. Dynamic - Index attribute mode: Span events are separate documents routed using attribute `elasticsearch.index`, with the following order of precedence: span event attribute -> scope attribute -> resource attribute if the attribute exists.
3. Dynamic - Data stream routing mode: For all documents, `data_stream.dataset` always ends with `.otel`. Span events are separate documents that have `data_stream.type: logs` and are routed using data stream attributes, with the following order of precedence: span event attribute -> scope attribute -> resource attribute.

The `elasticsearch.index` attribute is removed from the final document if it exists.

## Performance and batching

The exporter supports both internal batching and OpenTelemetry's standard `sending_queue` configuration:

### Internal batching (default)

By default, the exporter performs its own buffering and batching, as configured through the `flush` setting, unless the `sending_queue` and  `batcher` settings are defined.

### Using sending queue

The Elasticsearch exporter supports the `sending_queue` setting, which supports both queueing and batching. However, the sending queue is currently deactivated by default. You can turn on the sending queue by setting `sending_queue` to true. Batching support in sending queue is also deactivated by default and can be turned on by defining `sending_queue::batch`. For example:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    sending_queue:
      enabled: true
      batch:
        enabled: true
        min_size: 1000
        max_size: 10000
        timeout: 5s
```

## Bulk indexing

The Elasticsearch exporter uses the [Elasticsearch Bulk API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk) for indexing documents. Configure the behavior of bulk indexing with the following settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `num_workers` | `runtime.NumCPU()` | Number of workers publishing bulk requests concurrently. Note this isn't applicable if `batcher::enabled` is `true` or `false`. |
| `flush::bytes` | `5000000` | Write buffer flush size limit before compression. A bulk request are sent immediately when its buffer exceeds this limit. This value should be much lower than [Elasticsearch's `http.max_content_length`](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html#http-settings) config to avoid HTTP 413 Entity Too Large error. Keep this value under 5 MB. |
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

Starting from Elasticsearch 8.18 and higher, the [`include_source_on_error`](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-bulk#operation-bulk-include_source_on_error) query parameter allows users to receive the source document in the error response if there were parsing errors in the bulk request. In the exporter, the equivalent configuration is also named `include_source_on_error`.

- `include_source_on_error`:
  - `true`: Turns on bulk index responses to include source document on error. {applies_to}`stack: ga 8.18`
  - `false`: Turns off including source document on bulk index error responses. {applies_to}`stack: ga 8.18`
  - `null` (default): Backward-compatible option for older Elasticsearch versions. By default, the error reason is discarded from bulk index responses entirely. Only the error type is returned.

:::{warning}
The exporter might log error responses containing request payload, causing potential sensitive data to be exposed in logs.
:::

## Ingest pipeline support

Documents can be passed through an [Elasticsearch Ingest pipeline] before indexing. Use these settings to configure the ingest pipeline:

| Setting | Default | Description |
|---------|---------|-------------|
| `pipeline` | - | ID of an Elasticsearch Ingest pipeline used for processing documents published by the exporter. |
| `logs_dynamic_pipeline::enabled` | `false` | Turn on or off the dynamic pipeline. If `elasticsearch.ingest_pipeline` attribute exists in log record attributes and isn't empty, it's used as the Elasticsearch ingest pipeline. This currently only applies to the log signal. The attribute is removed from the final document when using `otel` mapping mode. |

For example:

```yaml subs=true
exporters:
  elasticsearch:
    endpoint: https://elasticsearch:9200
    pipeline: "my-custom-pipeline"
```

## Elasticsearch node discovery

The Elasticsearch Exporter regularly checks Elasticsearch for available nodes. Newly discovered nodes are automatically used for load balancing. 

The following settings are related to node discovery:

- `discover`:
  - `on_start` (optional): If enabled the exporter queries Elasticsearch
    for all known nodes in the cluster on startup.
  - `interval` (optional): Interval to update the list of Elasticsearch nodes.

To turn off node discovery, set `discover.interval` to `0`.

## Known limitations

The following are some known limitations of the Elasticsearch exporter:

- Metrics support is currently in development and might have limitations.
- Profile support requires Universal Profiling to be installed in {{es}}.
- Some mapping modes might have reduced functionality for certain telemetry types.
- The `bodymap` mode only supports logs and ignores other telemetry types.


## Known issues

The following are the main known issues with the Elasticsearch exporter:

| Issue | Cause | Solution |
|-------|-------|----------|
| **version_conflict_engine_exception** | TSDB data streams require unique documents per timestamp. Occurs with OTel mapping mode on Elasticsearch 8.16+ or ECS mode with system integration streams. | Update to Elasticsearch version 8.17.6 or higher and the Elasticsearch exporter version 0.121.0 or higher, or install a custom component template. Remove batch processors to prevent metric splitting. |
| **flush failed (400) illegal_argument_exception** | OTel mapping mode, which is default from version 0.122.0, requires Elasticsearch 8.12 or higher. | Upgrade Elasticsearch to 8.12 or higher or use alternative mapping modes. |

## Troubleshooting

When you encounter issues with the Elasticsearch exporter, you can try the following:

- Make sure your Elasticsearch version is compatible with your chosen mapping mode.
- Verify your API keys or credentials are valid and have appropriate permissions.
- Check that your Elasticsearch cluster supports the required features for your mapping mode.
