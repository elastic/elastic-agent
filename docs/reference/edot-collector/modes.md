---
navigation_title: Deployment modes
description: Deployment modes for the Elastic Distribution of OpenTelemetry (EDOT) Collector, including Agent and Gateway modes and when to use each.
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

# EDOT Collector deployment modes

You can deploy the EDOT Collector in different modes to meet your architectural needs. The two primary Collector modes are Agent and Gateway. Depending on your Elastic deployment type — Elastic self-managed, {{ecloud}}, or {{serverless-full}} — various EDOT Collector instances might be required in each mode to support the target architecture.

Use the information in the following sections to better understand deployment modes and patterns for your specific environment.

## EDOT Collector as Agent

In Agent mode, the EDOT Collector runs close to the data source, collecting telemetry data directly from the local environment. A Collector in Agent mode usually runs on the same host or virtual machine as the application or infrastructure component it is monitoring, or as a sidecar container or daemonset in Kubernetes.

Use the EDOT Collector in Agent mode when:

- You need to collect data directly from hosts or applications.
- You have a deployment with a small number of hosts.

## EDOT Collector as Gateway

In Gateway mode, the EDOT Collector acts as a central aggregation point, receiving data from multiple EDOT Agent collectors or instrumented applications before forwarding it to Elastic. The flexibility of the Gateway mode allows the Collector to centralize the scaling needs and data transformation operations of the data pipeline.

Use the EDOT Collector in Gateway mode when:

- You have multiple data sources or agents that need centralized processing or enrichment.
- You need to implement organization-wide processing rules.
- You want to reduce the number of connections to your Elastic backend.
- You need advanced pre-processing before data reaches Elastic.
- You're using a self-managed {{es}} deployment (required for APM functionality).
- You want to filter telemetry before it is shipped over the network to Elastic.

The Gateway pattern isn't exclusive to self-managed Elastic deployments. It's a general OpenTelemetry pattern that provides benefits in various scenarios:

- Kubernetes deployments: A Gateway collector centralizes cluster-level telemetry from multiple node-level Agent collectors.
- Multi-region deployments: Regional Gateway collectors aggregate data from multiple Agents before sending to a central destination.
- High-volume environments: Gateway collectors provide buffering and batching to handle high volumes of telemetry data.
- Complex processing: When advanced data transformation or filtering is needed before data reaches its destination.

### Gateway requirements for self-managed environments

For self-managed Elastic environments, you need a Gateway Collector deployed alongside your {{stack}}. The EDOT Collector in Gateway mode exposes a scalable OTLP endpoint, and performs data processing required for APM functionality.

This is the only case where using the {{es}} exporter is recommended. In all other EDOT Collector deployments described in this guide, use the OTLP exporter.

#### Required components for APM functionality in self-managed Elastic

The following components are required for APM functionality in self-managed Elastic:

- {applies_to}`edot_collector: ga 9.2` The `elasticapm` processor enriches trace data with additional attributes that improve the user experience in Elastic Observability UIs.
- The `elasticapm` connector generates pre-aggregated APM metrics from trace data.

In this case, EDOT Collector as a Gateway also handles routing of the different types of telemetry data to the relevant indices.

## Deployment in Kubernetes environments

In Kubernetes environments, EDOT Collectors are typically deployed in three distinct modes that work together to provide comprehensive observability:

### Agent mode in Kubernetes

In Kubernetes, the Agent mode is implemented in two forms:

| Form | Deployment | Functions |
|------|------------|-----------|
| Daemon form | DaemonSet on every node | - Collects node-local logs and host metrics.<br>- Receives telemetry data from applications instrumented with OpenTelemetry SDKs running on the node.<br>- Enriches application telemetry data with resource information such as host and Kubernetes metadata.<br>- Forwards all data to the Gateway Collector using the OTLP protocol. |
| Cluster form | Centralized service | - Collects Kubernetes cluster-level metrics from the Kubernetes API.<br>- Monitors cluster-wide resources that aren't specific to individual nodes.<br>- Forwards collected data to the Gateway Collector using the OTLP protocol. |

### Gateway mode in Kubernetes

The Gateway Collector in Kubernetes receives data from all Daemon and Cluster collectors. The Gateway performs additional pre-processing and aggregation for self-managed and {{ech}} deployments, and handles the final export to the appropriate Elastic backend.

This multi-tier architecture in Kubernetes provides an efficient way to collect and process telemetry data at different levels of the infrastructure while minimizing resource usage and network traffic.

For more details on Kubernetes deployment architecture, see [Kubernetes environments](opentelemetry://reference/architecture/k8s.md).

## Direct EDOT SDK to Managed OTLP (No Collector)

In some scenarios, you don't need a Collector at all. EDOT SDKs can send telemetry data directly to the [{{motlp}}](opentelemetry://reference/motlp.md). This is the simplest deployment pattern for getting application telemetry data into Elastic Observability.

Use direct EDOT SDK export to Managed OTLP when:

- You're sending data to the Managed OTLP Endpoint.
- You only need to collect application telemetry data.
- You want the simplest possible deployment.
- You don't need local data processing or filtering.
