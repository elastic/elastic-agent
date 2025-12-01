---
navigation_title: Attributes processor
description: The attributes processor is an OpenTelemetry Collector component that modifies resource attributes and span, metric, or log attributes before they are exported.
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

# Attributes processor

The attributes processor modifies telemetry attributes as they pass through the {{edot}} Collector pipeline. It can add, update, rename, hash, or delete attributes on spans, metrics, and logs before they reach downstream processors or exporters.

This processor is part of the core {{edot}} Collector distribution. It is useful when you need to normalize attribute names, remove sensitive fields, or enrich telemetry with additional context.

For full contrib details, refer to the [OpenTelemetry `attributesprocessor` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor).

## How it works

The attributes processor applies a list of **actions** to matching telemetry. Each action defines:

* Action type (such as `insert`, `update`, `delete`, `hash`, or `rename`)
* Target attribute key
* Optional value (for inserts/updates)
* Optional include/exclude match criteria

Actions run in order. Matching rules give fine-grained control over which spans, metrics, or logs the processor modifies.

## Typical use cases

The attributes processor is commonly used in {{product.observability}} pipelines to:

* Remove or transform sensitive attributes. For example, deleting user email fields or hashing IP addresses before they are exported.

* Normalize attribute naming across services. For example, converting custom key names (such as `"userId"`) to standard semantic conventions (`"user.id"`).

* Add static attributes, such as environment or cluster identifiers when they cannot be set at the source.

* Clean up noisy or irrelevant attributes. For example, removing temporary or dynamically generated labels that would otherwise create high-cardinality fields in {{es}}.

* Override or enrich resource attributes for standardizing deployment names, namespaces, or service metadata.

## Key configuration options

The following are the most important settings when configuring the attributes processor:

| Option | Description |
|--------|-------------|
| `actions` | A list of attribute modifications to apply. Each action uses the upstream-supported action types: `insert`, `update`, `upsert`, `delete`, `hash`, `extract`, `convert`, `rename`, `truncate`. |
| `include` / `exclude` | Rules for matching telemetry based on service name, span name, resource attributes, log severity, or metric name. |
| `match_type` | How attribute comparison is evaluated (`strict`, `regexp`, `expr`). |

For the complete list of configuration options and action-specific settings, refer to the [contrib `attributesprocessor` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor).

## Example configurations

The following example deletes a sensitive attribute, renames an attribute, inserts a cluster ID, and hashes an IP address before export:

```yaml
processors:
  attributes:
    actions:
      - key: user.email
        action: delete

      - key: userId
        action: rename
        new_key: user.id

      - key: cluster.id
        action: insert
        value: my-observability-cluster

      - key: client.ip
        action: hash
```

To enable the processor in a {{edot}} Collector pipeline:

```yaml
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [attributes]
      exporters: [elastic]
```

### Remove or obfuscate sensitive information from logs

Remove sensitive data from log attributes before export to comply with privacy regulations or security policies:

```yaml
processors:
  attributes:
    actions:
      # Delete sensitive fields - illustrative example (not real values)
      - key: user.password
        action: delete
      - key: credit_card.number
        action: delete
      - key: ssn 
        action: delete
      
      # Hash IP addresses for privacy
      - key: client.ip
        action: hash
      - key: server.ip
        action: hash
      
      # Remove authorization headers from HTTP spans
      - key: http.request.header.authorization
        action: delete
      - key: http.request.header.cookie
        action: delete
```

### Normalize attribute names across multiple services

Standardize attribute naming across different services that use inconsistent conventions:

```yaml
processors:
  attributes:
    actions:
      # Normalize user ID attributes
      - key: userId
        action: rename
        new_key: user.id
      - key: user_id
        action: rename
        new_key: user.id
      - key: UserID
        action: rename
        new_key: user.id
      
      # Normalize environment attributes
      - key: env
        action: rename
        new_key: deployment.environment
      - key: environment
        action: rename
        new_key: deployment.environment
      
      # Convert custom service names to semantic conventions
      - key: app.name
        action: rename
        new_key: service.name
```

### Add environment metadata conditionally

Enrich telemetry with environment-specific attributes based on service or resource attributes:

```yaml
processors:
  attributes:
    # Add cluster ID to all telemetry from production namespace
    include:
      match_type: strict
      resource_attributes:
        - key: k8s.namespace.name
          value: production
    actions:
      - key: cluster.id
        action: insert
        value: prod-cluster-01
      - key: environment
        action: insert
        value: production
      - key: region
        action: insert
        value: us-east-1
```

## Matching and filtering

You can limit attribute modifications to only specific spans, logs, or metrics using `include` and `exclude` blocks:

```yaml
processors:
  attributes:
    include:
      match_type: strict
      services: ["checkout-service"]
    actions:
      - key: http.request.header.authorization
        action: delete
```

This example removes an authorization header only from telemetry produced by the `checkout-service`.

:::{note}
Deleting keys like `http.request.header.authorization` only works if the key exists as a flattened attribute. Some SDKs store headers inside structured maps, which are not supported by the attributes processor.
:::

## Best practices and caveats

When using the attributes processor, keep these recommendations and constraints in mind:

* Plan action order carefully. Actions run sequentially, so a `delete` followed by an `update` on the same key will behave differently than the reverse order. Consider the sequence of operations when designing your attribute transformations.

* Use `include` and `exclude` filters to target specific telemetry. Instead of applying actions to all telemetry, limit modifications to specific services, spans, or metrics. This reduces processing overhead and prevents unintended side effects.

* Be cautious with dynamic attribute insertion. Inserting dynamically changing attributes can significantly increase cardinality in {{es}}, leading to performance issues and increased storage costs. Use static values or carefully controlled dynamic values to avoid high-cardinality issues.

* Consider downstream processor dependencies when renaming attributes. If later processors in your pipeline rely on specific attribute keys (for example, `service.name`), renaming those attributes can cause failures or unexpected behavior. Review your pipeline configuration to understand attribute dependencies.

* Understand that hashing is irreversible. Once hashed, attribute values cannot be retrieved or correlated using their original value. Use hashing for sensitive data that doesn't need to be queried or correlated later.

## Resources

* [Contrib component: attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor)
* [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)