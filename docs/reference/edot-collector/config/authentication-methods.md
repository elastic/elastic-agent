---
navigation_title: Authentication methods
description: Learn how to configure authentication for the EDOT Collector using API key authentication, bearer token authentication, and other security methods.
applies_to:
  stack: ga
  serverless: ga
  product:
    edot_collector: ga
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Authentication methods for the EDOT Collector

The {{edot}} Collector supports multiple authentication methods to secure connections and ensure only authorized clients can send telemetry data. This guide covers the available authentication extensions and how to configure them.

## Overview

Authentication in the EDOT Collector is handled through extensions that implement the `extensionauth` interface. These extensions can be used to:

- Authenticate incoming requests from SDKs and other collectors.
- Authenticate outgoing requests to external services.

## Available authentication extensions

The EDOT Collector supports the following authentication extensions:

### Elastic API Key Authentication (`apikeyauth`)

The `apikeyauth` extension is an Elastic-specific authentication method that validates Elasticsearch API keys against your {{es}} cluster. This extension is ideal for authenticating requests from EDOT SDKs and other Collectors that use Elasticsearch API keys.

### Bearer Token Authentication (`bearertokenauth`)

The `bearertokenauth` extension is an contrib OpenTelemetry authentication method that supports static bearer tokens. This extension is useful for token-based authentication scenarios.

## Configuration examples

These examples show how to configure the `apikeyauth` and `bearertokenauth` extensions.

### Elastic API key authentication

Configure the `apikeyauth` extension to authenticate incoming requests:

```yaml subs=true
extensions:
  apikeyauth:
    endpoint: "https://example.com:9200"
    application_privileges:
      - application: "apm"
        privileges: ["config_agent:read"]
        resources: ["*"]
    cache:
      capacity: 1000
      ttl: "5m"
      pbkdf2_iterations: 10000
      key_headers: ["X-Tenant-Id"]

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: apikeyauth
      http:
        auth:
          authenticator: apikeyauth

service:
  extensions: [apikeyauth]
```

#### Configuration options

The following configuration options are available for the `apikeyauth` extension:

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `endpoint` | string | The Elasticsearch endpoint for API key validation | Required |
| `application_privileges` | array | List of required application privileges and resources | Required |
| `application_privileges.application` | string | Name of the application for which privileges are defined | `""` |
| `application_privileges.privileges` | array | List of application-specific privileges that the API Key must have to be considered valid | `[]` |
| `application_privileges.resources` | array | List of application-specific resources that the API Key must have access to be considered valid | `[]` |
| `cache.capacity` | integer | Maximum number of cached entries | 1000 |
| `cache.ttl` | duration | Time-to-live for cached entries | 30s |
| `cache.pbkdf2_iterations` | integer | Number of PBKDF2 iterations for key derivation | 10000 |
| `cache.key_headers` | array | Optional headers to include in cache key generation | `[]` |

### Bearer token authentication

Configure the `bearertokenauth` extension for bearer token-based authentication:

```yaml subs=true
extensions:
  bearertokenauth:
    scheme: "Bearer"
    token: "your-secret-token"
    header: "Authorization"

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: bearertokenauth
      http:
        auth:
          authenticator: bearertokenauth

service:
  extensions: [bearertokenauth]
```

#### Configuration options

The following configuration options are available for the `bearertokenauth` extension:

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `scheme` | string | Authentication scheme | "Bearer" |
| `token` | string | Static token for authentication. Only required if `tokens` is an empty list and `filename` is empty. | `""` |
| `tokens` | string array | List of multiple tokens. Only required if `token` and `filename` are empty. | `[]` |
| `filename` | string | Path to file containing the token, required if `token` and `tokens` are left unset. | `""` |
| `header` | string | Custom header name | "Authorization" |

#### File-based token storage

For enhanced security, store tokens in files instead of configuration:

```yaml subs=true
extensions:
  bearertokenauth:
    scheme: "Bearer"
    filename: "/path/to/token/file"
    header: "Authorization"

service:
  extensions: [bearertokenauth]
```

The extension automatically monitors the token file for changes and reloads the token when the file is modified.

## Use cases

These use cases show how to configure the `apikeyauth` and `bearertokenauth` extensions for different scenarios.

### Authenticating EDOT SDKs

When using EDOT SDKs, configure the `apikeyauth` extension to validate API keys:

```yaml subs=true
extensions:
  apikeyauth:
    endpoint: "${ELASTIC_ENDPOINT}"
    application_privileges:
      - application: "apm"
        privileges: ["config_agent:read"]
        resources: ["*"]

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: apikeyauth
      http:
        auth:
          authenticator: apikeyauth
```

### Securing collector-to-collector communication

Use bearer token authentication for secure communication between collectors:

```yaml subs=true
extensions:
  bearertokenauth:
    scheme: "Collector"
    token: "collector-secret-token"

receivers:
  otlp:
    protocols:
      grpc:
        auth:
          authenticator: bearertokenauth
```

### Multi-tenant authentication

For multi-tenant environments, use the `apikeyauth` extension with tenant-specific headers:

```yaml subs=true
extensions:
  apikeyauth:
    endpoint: "${ELASTIC_ENDPOINT}"
    application_privileges:
      - application: "apm"
        privileges: ["config_agent:read"]
        resources: ["*"]
    cache:
      key_headers: ["X-Tenant-Id", "X-Organization-Id"]
```

## Security considerations

In general, be aware of the following security considerations:

### API Key security

- Store API keys securely using environment variables or secret management systems.
- Use the minimum required privileges for API keys.
- Regularly rotate API keys.
- Monitor API key usage and access patterns.

### Token security

- Use strong, randomly generated tokens.
- Store tokens in secure files with appropriate permissions.
- Avoid hardcoding tokens in configuration files.
- Consider using token rotation mechanisms.

## Troubleshooting

The following issues might occur.

:::{dropdown} API key validation failures
- Verify the Elasticsearch endpoint is accessible.
- Check API key permissions and application privileges.
- Ensure the API key is valid and not expired.
- Verify network connectivity and firewall rules.
:::

:::{dropdown} Bearer token authentication failures
- Confirm the token is correct and not expired.
- Check the authentication scheme matches expectations.
- Verify the token file exists and is readable.
- Ensure the custom header is properly configured.
:::

