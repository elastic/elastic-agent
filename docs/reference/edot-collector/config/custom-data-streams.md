---
navigation_title: Custom data stream routing
description: Customize data stream routing in EDOT. Learn scenarios, patterns, and risks when modifying `data_stream.namespace` or `data_stream.dataset`.
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

# Custom data stream routing with EDOT

{{edot}} (EDOT) uses opinionated defaults for data stream naming to ensure compatibility with Elastic dashboards, {{product.apm}} visualizations, and curated UIs.

While most use cases rely on these defaults, EDOT also supports advanced dynamic routing.

:::{important}
We strongly recommend not changing the default data stream names. Customizing data stream routing diverges from the standard ingestion model and there's no guarantee it will be valid for future versions.
:::

## When to customize data streams

The only recommended use case for customizing data stream routing is to separate data by environment (for example: dev, staging, and prod).

In this case, we recommend changing only `data_stream.namespace`, not `data_stream.dataset`.

## Modifying `namespace`

A data stream name follows this structure:

```
<type>-<dataset>-<namespace>
```

The `namespace` is intended as the configurable part of the name. Elastic dashboards, detectors, and UIs support multiple namespaces automatically.

## Why not modify `dataset`?

Changing the `dataset` value can cause:

- Dashboards and {{product.apm}} views to fail to load
- Loss of compatibility with built-in correlations and cross-linking
- Inconsistent field mappings
- Proliferation of data streams and increased shard counts

Only modify `dataset` if it's absolutely necessary and you're aware of the trade-offs.

## Configuration example

To enable dynamic data stream routing:

1. Set `mapping.mode: otel` in the {{es}} exporter. When using `otel` mapping mode, the exporter appends `.otel` to the `data_stream.dataset` value automatically.
2. Use a `resource` processor to set the desired `namespace` or `dataset` from resource attributes.
3. Add the processor to your pipeline.

:::{note}
The example is purely illustrative, with no guarantee of it being production ready.
:::

```yaml
exporters:
  elasticsearch/otel:
    api_key: ${env:ELASTIC_API_KEY}
    endpoints: [${env:ELASTIC_ENDPOINT}]
    mapping:
      mode: otel

processors:
  resource/env-namespace: # <-- make sure you are using `resource` and not `attributes`
    attributes:
      - key: data_stream.namespace
        from_attribute: k8s.namespace.name
        action: upsert

service:
  pipelines:
    metrics/otel:
      processors:
        - batch
        - resource/env-namespace # <-- add the processor to the pipeline
      exporters:
        - elasticsearch/otel
```

## Valid data stream names

Any dynamic value used in `data_stream.namespace` or `data_stream.dataset` must comply with {{es}} index naming rules:

- Lowercase only
- No spaces
- Must not start with `_`
- Must not contain: `"`, `\`, `*`, `,`, `<`, `>`, `|`, `?`, `/`
- Avoid hyphens in environment names (use `produs` instead of `prod-us`)

Invalid names prevent data stream creation.

## Risks and limitations

This configuration diverges from the standard ingestion model. Be aware of the following:

- Future EDOT versions may not support this configuration or may introduce breaking changes.
- Changes might lead to an increase in data streams and shard counts.
- Dashboards and UIs may not recognize non-standard datasets.
- Some data streams might fail to be created if there are non-allowed characters in the values set for `data_stream.namespace` or `data_stream.dataset`.

Use this feature only when necessary and validate in non-production environments first.

## Additional resources

- [Data stream routing reference](docs-content://solutions/observability/apm/opentelemetry/data-stream-routing.md)
- [EDOT Collector configuration examples](/reference/edot-collector/config/index.md)
