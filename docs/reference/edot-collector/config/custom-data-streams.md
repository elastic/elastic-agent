---
navigation_title: Custom data stream routing
description: Customize data stream routing in EDOT. Learn scenarios, patterns, and risks when modifying data_stream.namespace or data_stream.dataset.
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

{{edot}} (EDOT) uses opinionated defaults for data stream naming to ensure compatibility with Elastic dashboards, {{product.apm}} visualizations, and curated UIs. While most use cases rely on these defaults, EDOT also supports advanced dynamic routing.

:::{warning}
We strongly recommend not changing the default data stream names. Customizing data stream routing diverges from the standard ingestion model and there's no guarantee it will be valid for future versions.
:::

## When to customize data streams

The only recommended use case for customizing data stream routing is to separate data by environment (for example: dev, staging, and prod).

A data stream name follows this structure:

```
<type>-<dataset>-<namespace>
```

We recommend changing only `data_stream.namespace`, not `data_stream.dataset`.

### The `namespace` field

The `namespace` is intended as the configurable part of the name. Elastic dashboards, detectors, and UIs support multiple namespaces automatically.

### The `dataset` field

Only modify `dataset` if it's absolutely necessary and you're aware of the tradeoffs. Changing the `dataset` value can cause:

- Dashboards and {{product.apm}} views to fail to load
- Any other content pack that you end up installing to fail
- Loss of compatibility with built-in correlations and cross-linking
- Inconsistent field mappings
- Proliferation of data streams and increased shard counts
- Incompatibility with OpenTelemetry content packs, which are required to visualize OpenTelemetry data stored natively as OpenTelemetry semantic conventions

## Configuration example

To enable dynamic data stream routing:

1. Use a `transform` processor with OTTL (OpenTelemetry Transformation Language) to set the desired `namespace` or `dataset` from resource attributes. The transform processor allows routing at the scope or signal level, not just at the resource level, and is becoming the default for data manipulation and enrichment.
2. Add the processor to your pipeline.

When using the default `otel` mapping mode, the exporter appends `.otel` to the `data_stream.dataset` value automatically.

:::{note}
The example is purely illustrative, with no guarantee of it being production ready.
:::

```yaml
exporters:
  elasticsearch/otel:
    api_key: ${env:ELASTIC_API_KEY}
    endpoints: [${env:ELASTIC_ENDPOINT}]

processors:
  transform/env-namespace:
    error_mode: ignore
    metric_statements:
      - context: resource
        statements:
          - set(attributes["data_stream.namespace"], attributes["k8s.namespace.name"])

service:
  pipelines:
    metrics/otel:
      processors:
        - batch
        - transform/env-namespace
      exporters:
        - elasticsearch/otel
```

### Valid data stream names

Any dynamic value used in `data_stream.namespace` or `data_stream.dataset` must comply with {{es}} index naming rules:

- Lowercase only
- No spaces
- Must not start with `_`
- Must not contain: `"`, `\`, `*`, `,`, `<`, `>`, `|`, `?`, `/`
- Avoid hyphens in environment names (use `produs` instead of `prod-us`)

Invalid names prevent data stream creation.

### Risks and limitations

This configuration diverges from the standard ingestion model. Be aware of the following:

- Future EDOT versions may not support this configuration or may introduce breaking changes.
- Changes might lead to an increase in data streams and shard counts.
- Dashboards and UIs may not recognize non-standard datasets.
- OpenTelemetry content packs may not work with custom datasets. These content packs are required to visualize OpenTelemetry data stored natively as OpenTelemetry semantic conventions. Install content packs from the {{kib}} Integrations UI by searching for `otel`.
- Some data streams might fail to be created if there are non-allowed characters in the values set for `data_stream.namespace` or `data_stream.dataset`.

Use this feature only when necessary and validate in non-production environments first.

## Additional resources

- [Data stream routing reference](docs-content://solutions/observability/apm/opentelemetry/data-stream-routing.md)
- [EDOT Collector configuration examples](/reference/edot-collector/config/index.md)
