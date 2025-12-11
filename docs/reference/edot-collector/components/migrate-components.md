---
navigation_title: Migrate components
description: How to migrate from deprecated EDOT Collector components to their replacements.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector: ga
type: how-to
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Migrate from deprecated components

This guide explains how to migrate from deprecated EDOT Collector components to their replacements.

## Before you begin

- Make sure your {{product.elastic-stack}} is running version {{version.stack.base}}. If you're using {{product.elastic-stack}} version 8.18 or 8.19, continue using the deprecated components as specified in the configuration for your Stack version.
- Have access to a staging environment where you can test the new configuration before deploying to production.

## Migrate your configuration

Follow these steps to migrate your existing EDOT Collector configuration.

:::::{stepper}

::::{step} Download the latest default configuration
Download the configuration sample that matches your use case from the [default configuration samples](/reference/edot-collector/config/default-config-standalone.md#agent-mode). For Gateway mode, refer to the [Gateway mode section](/reference/edot-collector/config/default-config-standalone.md#gateway-mode).

The latest configurations for {{product.elastic-stack}} 9.x use the latest components instead of the deprecated ones.
::::

::::{step} Test the new configuration in staging
Before deploying to production, validate the new configuration in a staging environment:

1. Deploy the EDOT Collector with the new configuration to your staging environment.
2. Verify that telemetry data (logs, metrics, and traces) is being collected and exported correctly.
3. Check that the data appears correctly in the {{product.observability}} UIs in {{product.kibana}}.
4. Test any custom pipelines or configurations you might have added on top of the default configuration.

:::{tip}
If you have custom configurations, compare your existing configuration with the new default to identify which sections need updating.
:::
::::

::::{step} Apply the new configuration in production
After validating the configuration in staging:

1. Schedule a maintenance window for the update if necessary.
2. Back up your existing EDOT Collector configuration.
3. Deploy the new configuration to your production collectors.
4. Monitor the {{product.observability}} UIs to ensure data continues to flow correctly.
::::

:::::

::::{important}
If you're upgrading EDOT Collector to 9.x but keeping your {{product.elastic-stack}} on 8.18 or 8.19:

- Use the configuration examples for your Stack version (8.18 or 8.19), not the latest 9.x configuration.
- Continue using deprecated components that are included in the configuration for your Stack version.
- These deprecated components are retained in EDOT Collector 9.x specifically to maintain backwards compatibility during the official deprecation window.
::::

## Related pages

- [Default configuration (standalone)](/reference/edot-collector/config/default-config-standalone.md)
- [Components included in the EDOT Collector](/reference/edot-collector/components.md)
