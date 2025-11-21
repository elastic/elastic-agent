---
navigation_title: Attributes processor
description: The attributes processor is an OpenTelemetry Collector component that modifies resource and span, metric, or log attributes before they are exported.
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
| `actions` | A list of attribute modifications to apply. Each action uses the upstream-supported action types: `insert`, `update`, `upsert`, `delete`, `hash`, `extract`, `convert`, `rename`. |
| `include` / `exclude` | Rules for matching telemetry based on service name, span name, resource attributes, log severity, or metric name. |
| `match_type` | How attribute comparison is evaluated (`strict`, `regexp`, `expr`). |

For the complete list of configuration options and action-specific settings, refer to the [contrib `attributesprocessor` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor).

## Example configuration

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
      exporters: [elasticsearch]
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

## Best practices

Follow these recommendations when using the attributes processor:

* Plan action order carefully. Actions run sequentially, so a `delete` followed by an `update` on the same key will behave differently than the reverse order. Consider the sequence of operations when designing your attribute transformations.

* Use `include` and `exclude` filters to target specific telemetry instead of applying actions to all telemetry. This limits modifications to specific services, spans, or metrics, reducing processing overhead and preventing unintended side effects.

* Be cautious with dynamic attribute insertion, as inserting dynamically changing attributes may increase cardinality in {{es}}. Use static values or carefully controlled dynamic values to avoid high-cardinality issues.

* Consider downstream processor dependencies when renaming attributes. If later processors rely on a specific attribute key (for example, `service.name`), renaming it can break behavior. Review your pipeline configuration to understand attribute dependencies.

* Understand that hashing is irreversible. Once hashed, attribute values cannot be retrieved or correlated using their original value. Use hashing for sensitive data that doesn't need to be queried or correlated later.

## Caveats and limitations

Be aware of these constraints and behaviors when using the attributes processor:

* Action order affects results. Actions run sequentially, and the order matters. Plan your action sequence to achieve the desired transformations.

* Inserting dynamically changing attributes can significantly increase cardinality in {{es}}, leading to performance issues and increased storage costs.

* Renaming attributes can break downstream processors. If later processors in your pipeline rely on specific attribute keys, renaming those attributes can cause failures or unexpected behavior.

* Hashing is irreversible. Hashed attribute values cannot be decrypted or correlated with their original values. Use hashing only when you don't need to query or correlate the original data.

## Resources

* [Contrib component: attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/attributesprocessor)
* [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/)