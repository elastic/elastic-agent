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

The {{product.apm}} Config extension (`apmconfigextension`) enables central configuration for {{edot}} SDKs through the Open Agent Management Protocol (OpAMP). It establishes a control channel between the {{edot}} Collector and an OpAMP-enabled {{product.apm-server}} endpoint so that configuration updates can be retrieved and delivered dynamically to connected SDKs.

{applies_to}`stack: ga 9.1` This extension is required when using the [Central Configuration feature](docs-content://solutions/observability/apm/opentelemetry/edot-sdks-central-configuration.md) for {{edot}} SDKs.

For full contrib details, refer to the [OpenTelemetry `apmconfigextension` documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension).

## How it works

The extension acts as an OpAMP client, opening a bidirectional control channel to the OpAMP endpoint exposed by {{product.apm-server}}. Through this channel:

1. The Collector requests configuration bundles for connected {{edot}} SDKs.
2. The configuration server sends updates based on user changes in the Applications UI.
3. Updated configuration is distributed to {{edot}} SDKs using OpAMP-supported mechanisms.

The extension does not modify telemetry or manage pipelines. Its sole purpose is configuration synchronization.

## Typical use cases

Common scenarios where the {{product.apm}} Config extension is required:

* Central configuration for {{edot}} SDKs. Enables dynamic updates to sampling, attribute collection, security settings, and custom SDK options.

* Standalone {{edot}} Collector deployments. The extension can connect directly to the {{product.apm-server}} OpAMP endpoint.

* Managing large fleets of instrumented services. Allows consistent and centralized control of SDK configuration without requiring application restarts.

:::{note}
Integration with {{fleet}} Server (Fleet OpAMP endpoint) is not available at this time.
:::

## Example configuration

The following examples show how to configure the {{product.apm}} Config extension for different deployment scenarios:

### Standalone {{edot}} Collector

```yaml
extensions:
  bearertokenauth:
    scheme: "APIKey"
    token: "<ENCODED_ELASTICSEARCH_APIKEY>"

  apmconfig:
    opamp:
      protocols:
        http:
          endpoint: "https://apm.example.com:8200/opamp"
          
    source:
      elasticsearch:
        endpoint: "<ELASTICSEARCH_ENDPOINT>"
        auth:
          authenticator: bearertokenauth

service:
  extensions: [bearertokenauth, apmconfig]
```

### Custom OpAMP settings

You can configure timeouts or connection behavior:

```yaml
extensions:
  apmconfig:
    opamp:
      protocols:
        http:
          endpoint: "https://apm.example.com:8200/opamp"
          timeout: 30s
          tls:
            insecure_skip_verify: false
```

## Key configuration options

The following are the most important settings when configuring the {{product.apm}} Config extension:

| Option | Description |
|--------|-------------|
| `opamp.protocols.http.endpoint` | The OpAMP server endpoint. Required for standalone deployments. |
| `opamp.protocols.http.headers` | HTTP headers used for authentication, such as API keys. |
| `opamp.protocols.http.tls` | TLS options, including certificate verification behavior. |
| `opamp.protocols.http.timeout` | Timeout for OpAMP communication. |

:::{note}
The endpoint must point to an OpAMP-enabled {{product.apm-server}} Server. Standard ingest or OTLP endpoints will not work.
:::

For the complete list of configuration options, refer to the [contrib `apmconfigextension` documentation](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension).

## Resources

* [Contrib component: apmconfigextension](https://github.com/elastic/opentelemetry-collector-components/tree/main/extension/apmconfigextension)
* [OpAMP specification](https://opentelemetry.io/docs/specs/opamp/)
* [Central configuration for {{edot}} SDKs](docs-content://solutions/observability/apm/apm-agent-central-configuration.md)