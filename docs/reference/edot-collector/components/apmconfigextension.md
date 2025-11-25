---
navigation_title: APM Config extension
description: The APM Config extension is an OpenTelemetry Collector component that enables central configuration delivery for EDOT SDKs using the Open Agent Management Protocol (OpAMP).
applies_to:
  stack:
  serverless:
  observability:
  product:
    edot_collector:
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# APM Config extension

The {{product.apm}} Config extension (`apmconfigextension`) enables central configuration for {{edot}} SDKs through the Open Agent Management Protocol (OpAMP). It connects the {{edot}} Collector to the Elastic configuration server ({{product.apm-server}} or {{fleet}} Server) so that configuration updates can be retrieved and applied dynamically.

{applies_to}`stack: ga 9.1` This component is a core part of the {{edot}} Collector distribution and is required for enabling the [Central Configuration feature](docs-content://solutions/observability/apm/opentelemetry/edot-sdks-central-configuration.md) in {{product.observability}}.

For full contrib details, refer to the [OpenTelemetry `apmconfigextension` documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension).

## How it works

The extension acts as an OpAMP client, establishing a control channel between the Collector and the Elastic configuration server. Through this channel:

1. The Collector requests configuration bundles for connected {{edot}} SDKs.
2. The configuration server sends updates based on user changes in the Applications UI.
3. Updated configuration is distributed to {{edot}} SDKs using OpAMP-supported mechanisms.
4. The Collector reports status and metadata back to the server.

The extension does not modify telemetry or manage pipelines. Its sole purpose is configuration synchronization.

## Typical use cases

Common scenarios where the {{product.apm}} Config extension is required:

* Central configuration for {{edot}} SDKs. Enables dynamic updates to sampling, attribute collection, security settings, and custom SDK options.

* {{fleet}}-managed {{edot}} Collector deployments. When running inside {{agent}}, the extension integrates with {{fleet}} Server's OpAMP endpoint.

* Standalone {{edot}} Collector deployments. The extension can connect directly to the {{product.apm-server}} OpAMP endpoint when not using {{fleet}}.

* Managing large fleets of instrumented services. Allows consistent and centralized control of SDK configuration without requiring application restarts.

## Example configuration

The following examples show how to configure the {{product.apm}} Config extension for different deployment scenarios:

### Standalone {{edot}} Collector

```yaml
extensions:
  apmconfig:
    endpoint: "https://apm.example.com:8200"
    auth:
      api_key: "YOUR_API_KEY"

service:
  extensions: [apmconfig]
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [elasticsearch]
```

### {{edot}} Collector managed by {{agent}}

When using {{agent}}, the endpoint and authentication are provided automatically. A minimal configuration might look like this:

```yaml
extensions:
  apmconfig: {}

service:
  extensions: [apmconfig]
```

### Custom OpAMP settings

You can configure timeouts or connection behavior:

```yaml
extensions:
  apmconfig:
    endpoint: "https://fleet.example.com:8220"
    timeout: 30s
    tls:
      insecure_skip_verify: false
```

## Key configuration options

The following are the most important settings when configuring the {{product.apm}} Config extension:

| Option | Description |
|--------|-------------|
| `endpoint` | The OpAMP server endpoint. Required for standalone deployments; injected automatically under {{agent}}. |
| `auth` | Authentication settings. Supports `api_key` and other {{product.apm-server}} authentication methods. |
| `tls` | TLS options, including certificate verification behavior. |
| `timeout` | Timeout for OpAMP communication. |

:::{note}
The endpoint must point to an OpAMP-enabled {{product.apm-server}} or {{fleet}} Server. Standard ingest or OTLP endpoints will not work.
:::

For the complete list of configuration options, refer to the [contrib `apmconfigextension` documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension).

## Resources

* [Contrib component: apmconfigextension](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension)
* [OpAMP specification](https://opentelemetry.io/docs/specs/opamp/)
* [Central configuration for {{edot}} SDKs](docs-content://solutions/observability/apm/apm-agent-central-configuration.md)