---
navigation_title: Elastic APM intake receiver
description: The Elastic APM intake receiver is an OpenTelemetry Collector component that receives APM data from Elastic APM Agents.
applies_to:
  stack: ga 9.2
  serverless:
    observability:
  product:
    edot_collector: ga 9.2
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Elastic APM intake receiver

The Elastic APM intake receiver is an OpenTelemetry Collector component that receives APM data from classic Elastic APM Agents. The receiver supports the [Elastic Intake v2 protocol](https://github.com/elastic/apm-data/tree/main/input/elasticapm/docs/spec/v2) and behaves like the Elastic APM Server, so that telemetry is stored in the same format and using the same indices while going through the Collector. This allows users of classic APM agents to gradually migrate to OpenTelemetry and adapt their instrumentation to the new OTel-based approach.

:::{important}
Real user monitoring (RUM) intake and older intake protocols are not supported.
:::

## Get started

To use the Elastic APM intake receiver, include it in the receiver definitions of the [Collector configuration](/reference/edot-collector/config/index.md):

```yaml
receivers:
  elasticapmintake:
    agent_config:
      enabled: false
```

## Configuration

The Elastic APM intake receiver supports standard HTTP server configuration, including TLS/mTLS and authentication.

### TLS and mTLS settings

You can turn on TLS or mutual TLS to encrypt data in transit between Elastic APM agents and the receiver. Refer to [OpenTelemetry TLS server configuration](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#server-configuration) for more details.

For example:

```yaml
receivers:
  elasticapmintake:
    tls:
      cert_file: server.crt
      key_file: server.key
    agent_config:
      enabled: false
```

Refer to [OpenTelemetry TLS server configuration](https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#server-configuration) for more details.

### Authentication settings

In addition to TLS, you can configure authentication to make sure that only authorized agents can send data to the receiver. The Elastic APM intake receiver supports any `configauth` authenticator. 

Use the recommended`apikeyauth` extension to validate Elastic APM API keys. For example:

```yaml
extensions:
  apikeyauth:
    endpoint: "<YOUR_ELASTICSEARCH_ENDPOINT>"
    application_privileges:
      - application: "apm"
        privileges:
          - "event:write"
        resources:
          - "-"
receivers:
  elasticapmintake:
    auth:
      authenticator: apikeyauth
    tls:
      cert_file: server.crt
      key_file: server.key
    agent_config:
      enabled: false
```

### Agent environment variables

The Elastic APM intake receiver supports the following environment variables:

- `ELASTIC_APM_API_KEY`: The API key to use for authentication.
- `ELASTIC_APM_SERVER_URL`: The URL of the Elastic APM server.
- `ELASTIC_APM_SERVER_CERT`: The path to the server certificate file.
