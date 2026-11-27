---
navigation_title: Deployment patterns
description: Deployment patterns for Elastic Agent configured as an OTel Collector, including edge collectors and gateways and when to use each.
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

# {{agent}} deployment patterns

You can deploy {{agent}} in different patterns to meet your architectural needs. The two primary patterns are edge collector and gateway. Depending on your Elastic deployment type — Elastic self-managed, {{ecloud}}, or {{serverless-full}} — you might need several {{agent}} instances, each deployed in one of these patterns, to support the target architecture.

Use the information in the following sections to better understand the deployment patterns for your specific environment.

## Edge collector [edot-collector-as-agent]

As an edge collector, {{agent}} runs close to the data source, collecting telemetry data directly from the local environment. An edge collector usually runs on the same host or virtual machine as the application or infrastructure component it is monitoring, or as a sidecar container or daemonset in Kubernetes. OpenTelemetry documentation calls this the [agent deployment pattern](https://opentelemetry.io/docs/collector/deploy/agent/).

Deploy {{agent}} as an edge collector when:

- You need to collect data directly from hosts or applications.
- You have a deployment with a small number of hosts.

## Gateway [edot-collector-as-gateway]

As a gateway, {{agent}} acts as a central aggregation point, receiving data from multiple edge collectors or instrumented applications before forwarding it to Elastic. A gateway lets you centralize the scaling needs and data transformation operations of the data pipeline. OpenTelemetry documentation calls this the [gateway deployment pattern](https://opentelemetry.io/docs/collector/deploy/gateway/).

Deploy {{agent}} as a gateway when:

- You have multiple data sources or edge collectors that need centralized processing or enrichment.
- You need to implement organization-wide processing rules.
- You want to reduce the number of connections to your Elastic backend.
- You need advanced pre-processing before data reaches Elastic.
- You're using a self-managed {{es}} deployment (required for {{product.apm}} functionality).
- You want to filter telemetry before it is shipped over the network to Elastic.

The gateway pattern isn't exclusive to self-managed Elastic deployments. It's a general OpenTelemetry pattern that provides benefits in various scenarios:

- Kubernetes deployments: A gateway centralizes cluster-level telemetry from multiple node-level edge collectors.
- Multi-region deployments: Regional gateways aggregate data from multiple edge collectors before sending to a central destination.
- High-volume environments: Gateways provide buffering and batching to handle high volumes of telemetry data.
- Complex processing: When advanced data transformation or filtering is needed before data reaches its destination.

### Gateway requirements for self-managed environments

For self-managed Elastic environments, you need a gateway deployed alongside your {{stack}}. The gateway exposes a scalable OTLP endpoint, and performs data processing required for APM functionality.

This is the only case where using the {{es}} exporter is recommended. In all other {{agent}} deployments described in this guide, use the OTLP exporter.

#### Required components for {{product.apm}} functionality in self-managed Elastic

The following components are required for APM functionality in self-managed Elastic:

- {applies_to}`edot_collector: ga 9.2` The `elasticapm` processor enriches trace data with additional attributes that improve the user experience in Elastic Observability UIs.
- The `elasticapm` connector generates pre-aggregated APM metrics from trace data.

In this case, the gateway also handles routing of the different types of telemetry data to the relevant indices.

## Deployment in Kubernetes environments

In Kubernetes environments, {{agent}} instances are typically deployed in three distinct roles that work together to provide comprehensive observability:

### Edge collectors in Kubernetes [agent-mode-in-kubernetes]

In Kubernetes, edge collectors take two forms:

| Form | Deployment | Functions |
|------|------------|-----------|
| Daemon form | DaemonSet on every node | - Collects node-local logs and host metrics.<br>- Receives telemetry data from applications instrumented with OpenTelemetry SDKs running on the node.<br>- Enriches application telemetry data with resource information such as host and Kubernetes metadata.<br>- Forwards all data to the gateway using the OTLP protocol. |
| Cluster form | Centralized service | - Collects Kubernetes cluster-level metrics from the Kubernetes API.<br>- Monitors cluster-wide resources that aren't specific to individual nodes.<br>- Forwards collected data to the gateway using the OTLP protocol. |

### Gateway in Kubernetes [gateway-mode-in-kubernetes]

The gateway in Kubernetes receives data from all Daemon and Cluster instances. The gateway performs additional pre-processing and aggregation for self-managed and {{ech}} deployments, and handles the final export to the appropriate Elastic backend.

This multi-tier architecture in Kubernetes provides an efficient way to collect and process telemetry data at different levels of the infrastructure while minimizing resource usage and network traffic.

For more details on Kubernetes deployment architecture, see [Kubernetes environments](opentelemetry://reference/architecture/k8s.md).

## Direct SDK to Managed OTLP (No Collector) [direct-edot-sdk-to-managed-otlp-no-collector]

In some scenarios, you don't need a Collector at all. EDOT SDKs can send telemetry data directly to the [{{motlp}}](opentelemetry://reference/motlp.md). This is the simplest deployment pattern for getting application telemetry data into {{product.observability}}.

Use direct SDK export to Managed OTLP when:

- You're sending data to the Managed OTLP Endpoint.
- You only need to collect application telemetry data.
- You want the simplest possible deployment.
- You don't need local data processing or filtering.
