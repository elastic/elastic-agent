---
navigation_title: Kubelet stats receiver
description: The Kubelet stats receiver is an OpenTelemetry Collector component that collects node, pod, container, and volume resource metrics from the Kubernetes Kubelet.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector:
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Kubelet stats receiver

The Kubelet stats receiver collects Kubernetes node, pod, container, and volume metrics directly from the Kubelet API. It is enabled by default in several {{product.observability}} Kubernetes pipelines and is a core component of the {{edot}} Collector distribution.

This receiver queries the Kubelet's `/stats/summary` endpoint and converts the retrieved usage statistics into OpenTelemetry metrics. When configured, it automatically surfaces pre-built dashboards in {{product.observability}} for visualizing node CPU and memory usage, pod throttling, container metrics, and network/filesystem usage.

For full contrib details, refer to the [OpenTelemetry kubeletstats receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver).

## Typical use cases

Use the Kubelet stats receiver when you need:

* CPU, memory, network, and filesystem metrics for Kubernetes nodes.

* Fine-grained container CPU/memory usage for workloads running on each node.

* Filesystem and ephemeral storage usage for pods and containers.

* To combine node- and pod-level metrics with logs and traces to troubleshoot performance issues, resource saturation, and pod eviction behavior.

## Configuration

The following example shows a minimal Kubelet stats receiver configuration in an EDOT Collector pipeline.

```yaml
receivers:
  kubeletstats:
    auth_type: serviceAccount
    collection_interval: 30s
    endpoint: "${KUBELET_ENDPOINT}"        # for example: https://$NODE_IP:10250
    insecure_skip_verify: true             # or configure proper TLS
    metric_groups:
      - node
      - pod
      - container
      - volume

processors:
  batch: {}

exporters:
  otlp:
    endpoint: ${OTEL_EXPORTER_OTLP_ENDPOINT}

service:
  pipelines:
    metrics:
      receivers: [kubeletstats]
      processors: [batch]
      exporters: [otlp]
```

### Key configuration options

The following configuration parameters determine how the Kubelet stats receiver interacts with the Kubelet API and which metric groups are collected:

| Setting | Description |
|--------|-------------|
| `auth_type` | Authentication mechanism for talking to the Kubelet. Typically `serviceAccount` when the Collector runs as a DaemonSet. |
| `endpoint` | The Kubelet’s secure API endpoint, usually `https://<node-ip>:10250`. |
| `collection_interval` | How frequently the receiver scrapes Kubelet metrics. |
| `metric_groups` | Controls which metric groups to collect (`node`, `pod`, `container`, `volume`). |
| `insecure_skip_verify` | Whether to skip TLS certificate verification. For production, configure proper TLS if possible. |

For all available settings, refer to the [contrib configuration documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver#configuration).

## How it works in the EDOT Collector

In EDOT, the Kubelet stats receiver is typically used when:

* The Collector is deployed as a DaemonSet, scraping each node’s Kubelet locally.
* You want per-node and per-pod usage metrics without installing additional agents.
* The `kubernetes` or `system` metrics pipelines need pod-level resource context.

EDOT applies no custom modifications to the contrib receiver (its behavior is identical to contrib). It is pre-included and validated as supported within the EDOT distribution.

## Example: Collect node and pod metrics in Kubernetes

When you run the EDOT Collector as a DaemonSet, you can enable the Kubelet stats receiver with a minimal configuration like this:

```yaml
receivers:
  kubeletstats:
    auth_type: serviceAccount
    metric_groups: [node, pod, container]
```

This configuration collects:

* Node CPU and memory usage  
* Pod throttling  
* Container memory working set  
* Network and filesystem usage per node, pod, and container

## Caveats and limitations

Consider the following when deploying the Kubelet stats receiver:

* RBAC and TLS must be configured properly. When running as a DaemonSet, the service account usually has the needed permissions.

* Very low `collection_interval` values can increase Kubelet load.

* Metrics for ephemeral containers may not always appear depending on underlying Kubernetes version behavior.

* The receiver scrapes only the local node’s Kubelet when running as a DaemonSet. For centralized scraping, you must expose each node’s Kubelet securely (not recommended).