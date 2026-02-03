---
navigation_title: Default config (Standalone)
description: Default configuration of the EDOT Collector in standalone mode.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector: ga
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Default configuration of the EDOT Collector (standalone)

The default configuration of the {{edot}} (EDOT) Collector includes pipelines for the collection of logs, host metrics, and data from OpenTelemetry SDKs.

The EDOT Collector can run in [Agent](https://opentelemetry.io/docs/collector/deployment/agent/) or [Gateway](https://opentelemetry.io/docs/collector/deployment/gateway/) mode:

- Agent mode: The EDOT Collector ingests data from infrastructure and SDKs and forwards it to Elastic or to another collector running in Gateway mode.
- Gateway mode: The EDOT Collector ingests data from other collectors running in Agent mode and forwards it to Elastic.

## Agent mode

The following sample config files for Agent mode are available:

::::{tab-set}

:::{tab-item} Linux

| Use Cases | Direct ingestion into {{es}} | Managed OTLP Endpoint |
|---|---|---|
| Platform logs | [Logs - ES] | [Logs - OTLP] |
| Platform logs and host metrics | [Logs &#124; Metrics - ES] | [Logs &#124; Metrics - OTLP] |
| Platform logs, host metrics, <br> and application telemetry | [Logs &#124; Metrics &#124; App - ES]<br>(*default*) | [Logs &#124; Metrics &#124; App - OTLP]<br>(*default*) |

:::

:::{tab-item} Windows

| Use Cases | Direct ingestion into {{es}} | Managed OTLP Endpoint |
|---|---|---|
| Platform logs | [Logs - ES (Windows)] | [Logs - OTLP (Windows)] |
| Platform logs and host metrics | [Logs &#124; Metrics - ES (Windows)] | [Logs &#124; Metrics - OTLP (Windows)] |
| Platform logs, host metrics, <br> and application telemetry | [Logs &#124; Metrics &#124; App - ES (Windows)]<br>(*default*) | [Logs &#124; Metrics &#124; App - OTLP (Windows)]<br>(*default*) |

:::

::::

Use the previous example configurations as a reference when configuring your contrib Collector or customizing your EDOT Collector configuration.

The following sections describe the default pipelines by use cases.

### Direct ingestion into Elasticsearch

For self-managed and {{ech}} stack deployment use cases, ingest OpenTelemetry data from the EDOT Collector directly into {{es}} using the [`elasticsearch`] exporter.

Learn more about the configuration options for the `elasticsearch` exporter in the [corresponding documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/exporter/elasticsearchexporter/README.md#configuration-options).

The `elasticsearch` exporter comes with two relevant data ingestion modes:

- `ecs`: Writes data in backwards compatible {{product.ecs}} format. Original attribute names and semantics might be lost during translation.
- `otel`: OTel attribute names and semantics are preserved.

The goal of EDOT is to preserve OTel data formats and semantics as much as possible, so `otel` is the default mode for the EDOT Collector. Some use cases might require data to be exported in ECS format for backwards compatibility.

#### Logs collection pipeline

For logs collection, the default configuration uses the [`filelog`] receiver to read log entries from files. Also, the [`resourcedetection`] processor enriches the log entries with metadata about the corresponding host and operating system.

:::{note}
The `from_context: client_metadata` option in the `resource` processor only applies to transport-level metadata. It cannot extract custom application attributes.

To propagate such values into your telemetry, set them explicitly in your application code using EDOT SDK instrumentation. For more information, refer to [EDOT Collector doesn’t propagate client metadata](docs-content://troubleshoot/ingest/opentelemetry/edot-collector/metadata.md).
:::

Data is exported directly to {{es}} using the [`elasticsearch`] exporter in `OTel-native` mode.

#### Application and traces collection pipeline

The application pipeline in the EDOT Collector receives data from OTel SDKs through the [`OTLP`] receiver. While logs and metrics are exported verbatim into {{es}}, traces require two additional components.

{applies_to}`edot_collector: ga 9.2` The [`elasticapm` processor](../components/elasticapmprocessor.md) enriches trace data with additional attributes that improve the user experience in the {{product.observability}} UIs. In addition, the [`elasticapm` connector](../components/elasticapmconnector.md) generates pre-aggregated APM metrics from tracing data.

Application-related OTel data is ingested into {{es}} in OTel-native format using the [`elasticsearch`] exporter.

:::{note}
Both the `elasticapm` processor and the `elasticapm` connector are required for Elastic APM UIs to work properly. As they aren't included in the OpenTelemetry [Collector Contrib repository](https://github.com/open-telemetry/opentelemetry-collector-contrib), you can:

* Use the EDOT Collector with the available configuration to ingest data into {{es}}.
* [Build a custom, EDOT-like Collector](/reference/edot-collector/custom-collector.md) for ingesting data into {{es}}.
* Use Elastic's [managed OTLP endpoint](docs-content://solutions/observability/get-started/opentelemetry/quickstart/serverless/index.md) that does the enrichment for you.

If you're running EDOT Collector 9.x with Elastic Stack 8.18 or 8.19, use the deprecated `elastictrace` processor instead of `elasticapm` processor as specified in the configuration for your Stack version.
:::

#### Host metrics collection pipeline

The host metrics pipeline uses the [`hostmetrics`] receiver to collect `disk`, `filesystem`, `cpu`, `memory`, `process` and `network` metrics for the corresponding host.

For backwards compatibility, host metrics are translated into ECS-compatible system metrics using the [`elasticinframetrics`] processor. Finally, metrics are ingested in `ecs` format through the [`elasticsearch`] exporter.

The [`resourcedetection`] processor enriches the metrics with meta information about the corresponding host and operating system. The [`attributes`] and [`resource`] processor are used to set some fields for proper routing of the ECS-based system metrics data into corresponding {{es}} data streams.

:::{note}
:applies_to: edot_collector: ga 9.2

The `elasticinframetrics` processor is deprecated in EDOT Collector 9.2 but is retained for backwards compatibility. If you're running EDOT Collector 9.x with {{product.elastic-stack}} 8.18 or 8.19, continue using this processor as specified in the configuration for your Stack version.
:::

::::{important}
:::{include} ../_snippets/process-config.md
:::
::::

### Using the Managed OTLP Endpoint

When ingesting OTel data through the [{{motlp}}](opentelemetry://reference/motlp.md), all the enrichment that is required for an optimal experience in the Elastic solutions happens at the endpoint level and is transparent to users.

The Collector configuration for all use cases that involve the {{motlp}} is only concerned with local data collection and context enrichment.

Platform logs are scraped with the [`filelog`] receiver, host metrics are collected through the [`hostmetrics`] receiver and both signals are enriched with meta information through the [`resourcedetection`] processor.

Data from OTel SDKs is piped through the [`OTLP`] receiver directly to the OTLP exporter that sends data for all signals to the {{motlp}}.

With the {{motlp}}, there is no need to configure any Elastic-specific components, such as the [`elasticinframetrics`] and [`elasticapm`] processors, the [`elasticapm`] connector, or the [`elasticsearch`] exporter. Edge setup and configuration can be fully vendor agnostic.

### Batching configuration for contrib OpenTelemetry Collector

When using contrib or upstream OpenTelemetry collectors, the following batching configuration is recommended when sending data to the {{motlp}}:

```yaml
otlp/ingest:
  endpoint: <ingest endpoint>
  headers:
    Authorization: ApiKey <value>
  sending_queue:
    enabled: true
    sizer: bytes
    queue_size: 50000000 # 50MB uncompressed
    block_on_overflow: true
    batch:
      flush_timeout: 1s
      min_size: 1_000_000 # 1MB uncompressed
      max_size: 4_000_000 # 4MB uncompressed
```

The previous configuration leverages an in-memory queue and optimized batching defaults to improve throughput, minimize data loss, and maintain low end-to-end latency.

:::{note}
The previous configuration is already included in the {{edot}} Collector.
:::

## Gateway mode

In Gateway mode, the Collector ingests data from other Collectors running in Agent mode and forwards it to Elastic.

### Example configuration

The following example configuration files are available for the Gateway mode:

:::::{tab-set}

::::{tab-item} 9.x
% start:edot-gateway-9x-table
| Version | Configuration  |
|---------|----------------|
| 9.3     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/gateway.yml) |
| 9.2     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.2.5/internal/pkg/otel/samples/linux/gateway.yml) |
| 9.1     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.1.10/internal/pkg/otel/samples/linux/gateway.yml) |
| 9.0     | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.0.8/internal/pkg/otel/samples/linux/gateway.yml) |
% end:edot-gateway-9x-table
::::

::::{tab-item} 8.x
% start:edot-gateway-8x-table
| Version | Configuration  |
|---------|----------------|
| 8.19    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v8.19.11/internal/pkg/otel/samples/linux/gateway.yml) |
| 8.18    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v8.18.8/internal/pkg/otel/samples/linux/gateway.yml) |
| 8.17    | [Gateway mode](https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v8.17.10/internal/pkg/otel/samples/linux/gateway.yml) |
% end:edot-gateway-8x-table
::::
:::::

Use the previous example configurations as a reference when configuring your Gateway Collector or customizing your EDOT Collector configuration.

### Data collection

The EDOT Collector in Gateway mode collects data from other Collectors using the OTLP protocol. 

By default, the sample Gateway configuration listens on port `4317` for gRPC and port `4318` for HTTP.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317 # Listen on all interfaces
      http:
        endpoint: 0.0.0.0:4318 # Listen on all interfaces
```

### Data processing and transformation

The Gateway configuration includes several processors to transform and optimize the collected data:

```yaml
processors:
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
    send_batch_max_size: 0 # Prevents splitting metrics requests
    timeout: 1s
  elasticapm: {}
```

:::{note}
:applies_to: edot_collector: ga 9.2

The `elasticapm` processor replaces the deprecated `elastictrace` processor. If you're running EDOT Collector 9.x with Elastic Stack 8.18 or 8.19, use the `elastictrace` processor and the `elasticinframetrics` processor as specified in the Gateway configuration for your Stack version.
:::

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
```

### Pipeline configuration

The service section defines separate pipelines for different telemetry types:

- Metrics pipelines for infrastructure and OTel metrics
- Logs pipeline
- Traces pipeline
- Aggregated OTel metrics pipeline

Each pipeline connects specific receivers, processors, and exporters to handle different data types appropriately.

## Central configuration

The EDOT Collector can be configured to use [APM Agent Central Configuration](docs-content://solutions/observability/apm/apm-agent-central-configuration.md). Refer to [Central configuration docs](opentelemetry://reference/central-configuration.md) for more details.

To activate the central configuration feature, add the [`apmconfig`](https://github.com/elastic/opentelemetry-collector-components/blob/main/extension/apmconfigextension/README.md). For example:

```yaml
extensions:
  apikeyauth:
    endpoint: "${ELASTIC_ENDPOINT}"
    application_privileges:
      - application: "apm"
        privileges: ["config_agent:read"]
        resources: ["*"]

  apmconfig:
    opamp:
      protocols:
        http:
          auth:
            authenticator: apikeyauth
```

::::{note}
The EDOT Collector doesn't store or embed the {{es}} API key.

Each EDOT SDK sends its own API key in the `Authorization` header (for example: `Authorization: ApiKey <Base64(id:key)>`).

The `apikeyauth` extension only validates incoming API keys against {{es}}, ensuring they include the `apm` to `config_agent:read` privilege and `resources: ["*"]`.
::::

Create an API Key following [these instructions](docs-content://deploy-manage/api-keys/elasticsearch-api-keys.md). The API key must include the application privilege `config_agent:read` with resources set to `"*"`.

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

The `apmconfig` extension supports any `configauth` authenticator. Use the `apikeyauth` extension to authenticate with {{es}} API keys:

```yaml
extensions:
  apikeyauth:
    endpoint: "${ELASTIC_ENDPOINT}"
    application_privileges:
      - application: "apm"
        privileges: ["config_agent:read"]
        resources: ["*"]

  apmconfig:
    opamp:
      protocols:
        http:
          auth:
            authenticator: apikeyauth
```

Create an API key with the minimum required application permissions through {{kib}} under **Observability** → **Applications** → **Settings** → **Agent Keys**, or by using the Elasticsearch Security API:

::::{dropdown} Example JSON payload
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
::::

The server expects incoming HTTP requests to include an API key with sufficient privileges, using the following header format: `Authorization: ApiKey <base64(id:api_key)>`.

### Secure SDK to Collector connection (TLS)

To secure the connection between the {{edot}} SDKs and the EDOT Collector, configure TLS on both ends.

#### SDK configuration

Set the following environment variables in your application:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example.com:4318
OTEL_EXPORTER_OTLP_INSECURE=false
OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/ssl/certs/collector-ca.crt
```

These settings:

* Enable TLS (`INSECURE=false`)

* Trust the Collector's certificate (`CERTIFICATE`)

* Ensure the endpoint uses `https://`

These settings work with .NET, Java, and Python SDKs.

#### Collector receiver configuration

Enable TLS in the OTLP receiver:

```yaml
receivers:
      # Receives data from other Collectors in Agent mode
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317 # Listen on all interfaces
            tls:
              cert_file: "/etc/ssl/certs/collector-server.crt"
              key_file: "/etc/ssl/private/collector-server.key"
          http:
            endpoint: 0.0.0.0:4318 # Listen on all interfaces
            tls:
              cert_file: "/etc/ssl/certs/collector-server.crt"
              key_file: "/etc/ssl/private/collector-server.key"
```

This encrypts data between SDKs and the Collector over both gRPC and HTTP protocols.

### Secure the connection between the EDOT Collector and Elastic

After securing communication between the {{edot}} SDKs and the `apmconfigextension`, you should secure the connection between the EDOT Collector and {{es}} endpoints.

The EDOT Collector uses the `elasticsearch/otel` or `elasticsearch/ecs` exporter to send telemetry data to Elastic. Elastic recommends using HTTPS to encrypt the connection and verify the server's certificate.

Example configuration:

```yaml
exporters:
  elasticsearch/otel:
    endpoint: "https://example.elastic.co:443"
    api_key: "<your-api-key>"
    tls:
      insecure: false
```

This setup encrypts data in transit and uses the system's default set of trusted certificate authorities to verify the Elastic endpoint certificate.

For {{ecloud}}, this is the recommended approach. {{ecloud}} certificates are signed by a public certificate authority (ISRG Root X1, Let's Encrypt), which should already be trusted by your system.

To override the default CA bundle, specify the CA file explicitly:

```yaml
tls:
  insecure: false
  ca_file: "/path/to/elastic-ca.crt"
```
:::{note}
Avoid using the CA certificate provided in the {{ecloud}} console to verify the Elastic endpoint. It is not intended for this purpose and might not work as expected.
:::

#### Mutual TLS (mTLS)

For self-managed Elastic deployments, you can optionally enable mTLS to authenticate both the Collector and the {{es}} endpoint. For example:

```yaml
exporters:
  elasticsearch/otel:
    endpoint: "https://example.elastic.co:443"
    api_key: "<your-api-key>"
    tls:
      ca_file: "/path/to/elastic-ca.crt"
      cert_file: "/path/to/client.crt"
      key_file: "/path/to/client.key"
      insecure: false
```

mTLS ensures that only authorized collectors can send telemetry data.

For {{ecloud}} and {{serverless-full}} deployments, mTLS is not required. TLS and API key authentication are enforced automatically.

## Configuration compatibility with Elastic Stack versions

While EDOT Collector 9.x is compatible with {{product.elastic-stack}} 8.18 and 8.19, users running these Stack versions should use the EDOT Collector configuration aligned with their Stack version to ensure the end-to-end experience works properly with {{product.kibana}} Observability UIs. Refer to [Migrate components](/reference/edot-collector/components/migrate-components.md) to migrate your configuration to the new components.

::::{important}
If you're upgrading EDOT Collector to 9.x but keeping your {{product.elastic-stack}} on 8.18 or 8.19:

- Use the configuration examples for your Stack version (8.18 or 8.19), not the latest 9.x configuration.
- Continue using deprecated components (such as `elasticinframetrics` and `elastictrace` processors) that are included in the configuration for your Stack version.
- These deprecated components are retained in EDOT Collector 9.x specifically to maintain backwards compatibility during the official deprecation window.

For Gateway mode configurations by Stack version, refer to the [Gateway mode section](#gateway-mode).
::::

[`attributes`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor
[`filelog`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver
[`hostmetrics`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver
[`elasticsearch`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter
[`elasticinframetrics`]: https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor
[`elasticapm` processor]: https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticapmprocessor
[`elasticapm` connector]: ../components/elasticapmconnector.md
[`resource`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor
[`resourcedetection`]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor
[`OTLP`]: https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver
% start:edot-samples-links
[Logs - ES]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/platformlogs.yml
[Logs - OTLP]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/managed_otlp/platformlogs.yml
[Logs &#124; Metrics - ES]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/platformlogs_hostmetrics.yml
[Logs &#124; Metrics - OTLP]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/managed_otlp/platformlogs_hostmetrics.yml
[Logs &#124; Metrics &#124; App - ES]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/logs_metrics_traces.yml
[Logs &#124; Metrics &#124; App - OTLP]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/linux/managed_otlp/logs_metrics_traces.yml
[Logs - ES (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/platformlogs.yml
[Logs - OTLP (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/managed_otlp/platformlogs.yml
[Logs &#124; Metrics - ES (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/platformlogs_hostmetrics.yml
[Logs &#124; Metrics - OTLP (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/managed_otlp/platformlogs_hostmetrics.yml
[Logs &#124; Metrics &#124; App - ES (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/logs_metrics_traces.yml
[Logs &#124; Metrics &#124; App - OTLP (Windows)]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/tags/v9.3.0/internal/edot/samples/windows/managed_otlp/logs_metrics_traces.yml

% end:edot-samples-links
[Gateway mode]: https://raw.githubusercontent.com/elastic/elastic-agent/refs/heads/main/internal/edot/samples/linux/gateway.yml
