---
title: Default configuration of the EDOT Collector (Standalone)
description: Default configuration of the EDOT Collector in standalone mode.
url: https://docs-v3-preview.elastic.dev/reference/edot-collector/config/default-config-standalone
products:
  - Elastic Agent
  - Elastic Cloud Serverless
  - Elastic Distribution of OpenTelemetry Collector
  - Elastic Observability
---

# Default configuration of the EDOT Collector (Standalone)

The default configuration of the Elastic Distribution of OpenTelemetry (EDOT) Collector includes pipelines for the collection of logs, host metrics, and data from OpenTelemetry SDKs.
The EDOT Collector can run in [Agent](https://opentelemetry.io/docs/collector/deployment/agent/) or [Gateway](https://opentelemetry.io/docs/collector/deployment/gateway/) mode:
- Agent mode: The EDOT Collector ingests data from infrastructure and SDKs and forwards it to Elastic or to another collector running in Gateway mode.
- Gateway mode: The EDOT Collector ingests data from other collectors running in Agent mode and forwards it to Elastic.


## Agent mode

The following sample config files for Agent mode are available:

| Use Cases                                               | Direct ingestion into Elasticsearch                                                                                                                                                                  | Managed OTLP Endpoint                                                                                                                                                                                                 |
|---------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Platform logs                                           | [Logs - ES](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/platformlogs.yml)Logs - ES                                                      | [Logs - OTLP](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/managed_otlp/platformlogs.yml)Logs - OTLP                                                      |
| Platform logs and host metrics                          | [Logs  Metrics - ES](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/platformlogs_hostmetrics.yml)Logs  Metrics - ES                        | [Logs  Metrics - OTLP](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/managed_otlp/platformlogs_hostmetrics.yml)Logs  Metrics - OTLP                        |
| Platform logs, host metrics,  and application telemetry | [Logs  Metrics  App - ES](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/logs_metrics_traces.yml)Logs  Metrics  App - ES(*default*default) | [Logs  Metrics  App - OTLP](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.3/internal/pkg/otel/samples/linux/managed_otlp/logs_metrics_traces.yml)Logs  Metrics  App - OTLP(*default*default) |

Use the previous example configurations as a reference when configuring your contrib Collector or customizing your EDOT Collector configuration.
The following sections describe the default pipelines by use cases.

### Direct ingestion into Elasticsearch

For self-managed and Elastic Cloud Hosted stack deployment use cases, ingest OpenTelemetry data from the EDOT Collector directly into Elasticsearch using the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter.
Learn more about the configuration options for the `elasticsearch` exporter in the [corresponding documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/elasticsearchexporter/README.md#configuration-options).
The `elasticsearch` exporter comes with two relevant data ingestion modes:
- `ecs`: Writes data in backwards compatible Elastic Common Schema (ECS) format. Original attribute names and semantics might be lost during translation.
- `otel`: OTel attribute names and semantics are preserved.

The goal of EDOT is to preserve OTel data formats and semantics as much as possible, so `otel` is the default mode for the EDOT Collector. Some use cases might require data to be exported in ECS format for backwards compatibility.

#### Logs collection pipeline

For logs collection, the default configuration uses the [`filelog`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) receiver to read log entries from files. In addition, the [`resourcedetection`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) processor enriches the log entries with metadata about the corresponding host and operating system.
<note>
  The `from_context: client_metadata` option in the `resource` processor only applies to transport-level metadata. It cannot extract custom application attributes.To propagate such values into your telemetry, set them explicitly in your application code using EDOT SDK instrumentation. For more information, refer to [EDOT Collector doesn’t propagate client metadata](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/troubleshoot/ingest/opentelemetry/edot-collector/metadata).
</note>

Data is exported directly to Elasticsearch using the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter in `OTel-native` mode.

#### Application and traces collection pipeline

The application pipeline in the EDOT Collector receives data from OTel SDKs through the [`OTLP`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) receiver. While logs and metrics are exported verbatim into Elasticsearch, traces require two additional components.
The [`elastictrace`](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elastictraceprocessor) processor enriches trace data with additional attributes that improve the user experience in the Elastic Observability UIs. In addition, the [`elasticapm`](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector) connector generates pre-aggregated APM metrics from tracing data.
Application-related OTel data is ingested into Elasticsearch in OTel-native format using the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter.
<note>
  Both components, `elastictrace` and `elasticapm` are required for Elastic APM UIs to work properly. As they aren't included in the OpenTelemetry [Collector Contrib repository](https://github.com/open-telemetry/opentelemetry-collector-contrib), you can:
  - Use the EDOT Collector with the available configuration to ingest data into Elasticsearch.
  - [Build a custom, EDOT-like Collector](https://docs-v3-preview.elastic.dev/reference/edot-collector/custom-collector) for ingesting data into Elasticsearch.
  - Use Elastic's [managed OTLP endpoint](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/solutions/observability/get-started/opentelemetry/quickstart/quickstart/serverless) that does the enrichment for you.
</note>


#### Host metrics collection pipeline

The host metrics pipeline uses the [`hostmetrics`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver) receiver to collect `disk`, `filesystem`, `cpu`, `memory`, `process` and `network` metrics for the corresponding host.
For backwards compatibility, host metrics are translated into ECS-compatible system metrics using the [`elasticinframetrics`](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor) processor. Finally, metrics are ingested in `ecs` format through the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter.
The [`resourcedetection`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) processor enriches the metrics with meta information about the corresponding host and operating system. The [`attributes`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor) and [`resource`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor) processor are used to set some fields for proper routing of the ECS-based system metrics data into corresponding Elasticsearch data streams.
<important>

  Process metrics are turned off by default to avoid generating a large volume of timeseries data. To turn on process metrics, uncomment or add the following section inside the `hostmetrics` receiver configuration:
  ```yaml
    process:
       mute_process_exe_error: true
       mute_process_io_error: true
       mute_process_user_error: true
       metrics:
          process.threads:
          enabled: true
          process.open_file_descriptors:
          enabled: true
          process.memory.utilization:
          enabled: true
          process.disk.operations:
          enabled: true
  ```
</important>


### Using the Managed OTLP Endpoint

When ingesting OTel data through the [Elastic Cloud Managed OTLP Endpoint](https://docs-v3-preview.elastic.dev/elastic/opentelemetry/tree/main/reference/motlp), all the enrichment that is required for an optimal experience in the Elastic solutions happens at the endpoint level and is transparent to users.
The Collector configuration for all use cases that involve the Elastic Cloud Managed OTLP Endpoint is only concerned with local data collection and context enrichment.
Platform logs are scraped with the [`filelog`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) receiver, host metrics are collected through the [`hostmetrics`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver) receiver and both signals are enriched with meta information through the [`resourcedetection`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) processor.
Data from OTel SDKs is piped through the [`OTLP`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) receiver directly to the OTLP exporter that sends data for all signals to the Elastic Cloud Managed OTLP Endpoint.
With the Elastic Cloud Managed OTLP Endpoint, there is no need to configure any Elastic-specific components, such as [`elasticinframetrics`](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor), [`elastictrace`](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elastictraceprocessor) processors, the [`elasticapm`](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector) connector, or the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter. Edge setup and configuration can be 100% vendor agnostic.

## Gateway mode

In Gateway mode, the Collector ingests data from other Collectors running in Agent mode and forwards it to Elastic.

## Example configuration

The following example configuration files are available for the Gateway mode:

| Version | Configuration                                                                                                                                     |
|---------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 8.17    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.0.4/internal/pkg/otel/samples/linux/gateway.yml)Gateway mode  |
| 8.18    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.0.4/internal/pkg/otel/samples/linux/gateway.yml)Gateway mode  |
| 9.0     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.0.4/internal/pkg/otel/samples/linux/gateway.yml)Gateway mode  |
| 8.19    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v8.19.0/internal/pkg/otel/samples/linux/gateway.yml)Gateway mode |
| 9.1     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.0/internal/pkg/otel/samples/linux/gateway.yml)Gateway mode  |

Use the previous example configuration as a reference when configuring your Gateway Collector or customizing your EDOT Collector configuration.

### Data collection and processing

The EDOT Collector in Gateway mode collects data from other Collectors using the OTLP protocol. By default, the sample Gateway configuration listens on port `4317` for gRPC and port `4318` for HTTP.
```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
```

The routing connector splits infrastructure metrics from other metrics and routes them to the appropriate Elastic Common Schema pipelines. Other metrics are exported in OTel-native format through the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter.
```yaml
connectors:
  routing:
    default_pipelines: [metrics/otel]
    error_mode: ignore
    table:
      - context: metric
        statement: route() where IsMatch(instrumentation_scope.name, "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver/internal/scraper/*")
        pipelines: [metrics/infra/ecs, metrics/otel]
  elasticapm: {}
```


### Data processing and transformation

The Gateway configuration includes several processors to transform and optimize the collected data:
```yaml
processors:
  elasticinframetrics:
    add_system_metrics: true
    drop_original: true
  attributes/dataset:
    actions:
      - key: event.dataset
        from_attribute: data_stream.dataset
        action: upsert
  resource/process:
    attributes:
      - key: process.executable.name
        action: delete
      - key: process.executable.path
        action: delete
  batch:
    send_batch_size: 1000
    timeout: 1s
    send_batch_max_size: 1500
  batch/metrics:
    send_batch_max_size: 0
    timeout: 1s
  elastictrace: {}
```


### Data export

The Gateway exports data to Elasticsearch in two formats:
- OTel-native format using the `elasticsearch/otel` exporter.
- Elastic Common Schema (ECS) format using the `elasticsearch/ecs` exporter.

```yaml
exporters:
  elasticsearch/otel:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}
    mapping:
      mode: otel
  elasticsearch/ecs:
    endpoints:
      - ${ELASTIC_ENDPOINT}
    api_key: ${ELASTIC_API_KEY}
    mapping:
      mode: ecs
```


### Pipeline configuration

The service section defines separate pipelines for different telemetry types:
- Metrics pipelines for infrastructure and OTel metrics
- Logs pipeline
- Traces pipeline
- Aggregated OTel metrics pipeline

Each pipeline connects specific receivers, processors, and exporters to handle different data types appropriately.

## Central configuration

The EDOT Collector can be configured to use [APM Agent Central Configuration](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/solutions/observability/apm/apm-agent-central-configuration). Refer to [Central configuration docs](https://docs-v3-preview.elastic.dev/elastic/opentelemetry/tree/main/reference/central-configuration) for more details.
To activate the central configuration feature, add the [`apmconfig`](https://github.com/elastic/opentelemetry-collector-components/blob/main/extension/apmconfigextension/README.md). For example:
```yaml
extensions:
  bearertokenauth:
    scheme: "APIKey"
    token: "<ENCODED_ELASTICSEARCH_APIKEY>"

  apmconfig:
    opamp:
      protocols:
        http:
          # Default is localhost:4320
          # endpoint: "<CUSTOM_OPAMP_ENDPOINT>"
    source:
      elasticsearch:
        endpoint: "<ELASTICSEARCH_ENDPOINT>"
        auth:
          authenticator: bearertokenauth
```

<note>
  For comprehensive authentication configuration options, see [Authentication methods](https://docs-v3-preview.elastic.dev/reference/edot-collector/config/authentication-methods).
</note>

Create an API Key following [these instructions](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/deploy-manage/api-keys/elasticsearch-api-keys). The API key must have `config_agent:read` permissions and resources set to `-`.

## Secure connection

To secure the connection between the EDOT Collector and Elastic, you can use TLS or mutual TLS, as well as the `apikeyauth` extension.

### TLS configuration

You can turn on TLS or mutual TLS to encrypt data in transit between EDOT SDKs and the extension. Refer to [OpenTelemetry TLS server configuration](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#server-configuration) for more details.
For example:
```yaml
extensions:
  apmconfig:
    opamp:
      protocols:
        http:
          endpoint: ":4320"
          tls:
            cert_file: server.crt
            key_file: server.key
   ...
```


### Authentication settings

In addition to TLS, you can configure authentication to ensure that only authorized agents can communicate with the extension and retrieve their corresponding remote configurations.
The `apmconfig` extension supports any configauth authenticator. Use the `apikeyauth` extension to authenticate with Elasticsearch API keys:
```yaml
extensions:
  apikeyauth:
    endpoint: "<YOUR_ELASTICSEARCH_ENDPOINT>"
    application_privileges:
      - application: "apm"
        privileges:
          - "config_agent:read"
        resources:
          - "-"
  apmconfig:
    opamp:
      protocols:
        http:
          auth:
            authenticator: apikeyauth
   ...
```

Create an API key with the minimum required application permissions through Kibana under **Observability** → **Applications** → **Settings** → **Agent Keys**, or by using the Elasticsearch Security API:
<dropdown title="Example JSON payload">

  ```json
  POST /_security/api_key
  {
    "name": "apmconfig-opamp-test-sdk",
    "metadata": {
      "application": "apm"
    },
    "role_descriptors": {
      "apm": {
        "cluster": [],
        "indices": [],
        "applications": [
          {
            "application": "apm",
            "privileges": [
              "config_agent:read"
            ],
            "resources": [
              "*"
            ]
          }
        ],
        "run_as": [],
        "metadata": {}
      }
    }
  }
  ```
</dropdown>

The server expects incoming HTTP requests to include an API key with sufficient privileges, using the following header format: `Authorization: ApiKey <base64(id:api_key)>`.