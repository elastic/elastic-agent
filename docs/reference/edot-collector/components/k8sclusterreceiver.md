---
navigation_title: Kubernetes cluster receiver
description: The Kubernetes cluster receiver is an OpenTelemetry Collector component that collects Kubernetes cluster-level metrics and entity events for Elastic Observability through the EDOT Collector.
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

# Kubernetes cluster receiver

The Kubernetes cluster receiver (`k8s_cluster`) is a core component of the {{edot}} (EDOT) Collector. It collects cluster-level metrics and entity events from the Kubernetes API server, enabling observability into node health, resource allocation, and workload states in Elastic Observability.

For full contrib details, refer to the [OpenTelemetry k8s_cluster receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver).



## Get started

To use the Kubernetes cluster receiver, include it in the receivers section of your Collector configuration.

The receiver is already included in the default {{edot}} Collector distribution.

```yaml
receivers:
  k8s_cluster:
    auth_type: serviceAccount
```

You can then reference it in your service pipelines to collect cluster-level metrics and entity events:

```yaml
service:
  pipelines:
    metrics:
      receivers: [k8s_cluster]
      exporters: [elasticsearch]
```

:::{note}
When deploying with the {{edot}} Helm chart, the `k8s_cluster` receiver runs as a single instance per cluster by default. If you’re configuring the Collector manually, ensure only one active instance of this receiver runs per cluster to avoid duplicate data.
:::


## How it works

The receiver authenticates to the Kubernetes API using a service account, kubeconfig, or no authentication, and continuously watches cluster objects such as Pods, Nodes, Deployments, and StatefulSets.

The receiver can coordinate multiple instances using the `k8s_leader_elector` extension, ensuring only one active collector scrapes data at any given time.


## Configuration

Example minimal configuration:

```yaml
receivers:
  k8s_cluster:
    auth_type: serviceAccount
    collection_interval: 10s
    metadata_collection_interval: 5m
    node_conditions_to_report: [Ready]
    allocatable_types_to_report: [cpu, memory]

exporters:
  elasticsearch:
    endpoints: [${ELASTIC_ENDPOINT}]
    api_key: ${ELASTIC_API_KEY}

service:
  pipelines:
    metrics:
      receivers: [k8s_cluster]
      exporters: [elasticsearch]
    logs/entity_events:
      receivers: [k8s_cluster]
      exporters: [elasticsearch]
```



### Key settings

The following configuration options control how the receiver connects to the Kubernetes API and emits metrics.

| Setting | Description | Default |
|----------|--------------|----------|
| `auth_type` | Authentication method used. (`none`, `serviceAccount`, or `kubeConfig`). | `serviceAccount` |
| `collection_interval` | How frequently metrics are emitted. | `10s` |
| `metadata_collection_interval` | How often cluster metadata is refreshed. Set to `0` to turn off. | `5m` |
| `node_conditions_to_report` | List of node conditions to report (for example `Ready`, `MemoryPressure`). | `[Ready]` |
| `allocatable_types_to_report` | Resource types to report (`cpu`, `memory`, `ephemeral-storage`, `pods`). When empty, no allocatable metrics are emitted. | `[]` (unless explicitly configured) |
| `distribution` | Kubernetes distribution used. (`kubernetes` or `openshift`). | `kubernetes` |
| `namespaces` | Limit observation to specific namespaces. Cluster-level objects (like Nodes) won’t be collected. | None |

For the full configuration schema, refer to [contrib `config.go`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/k8sclusterreceiver/config.go).



## Metrics overview

The `k8s_cluster` receiver emits a comprehensive set of metrics describing the state and resource usage of cluster entities.

Some key metric categories include:

| Metric prefix | Description | Example |
|----------------|--------------|----------|
| `k8s.node.*` | Node-level conditions, allocatable resources, and status. | `k8s.node.condition_ready`, `k8s.node.allocatable_cpu` |
| `k8s.pod.*` | Pod lifecycle and phase metrics. | `k8s.pod.phase`, `k8s.pod.status_reason` |
| `k8s.container.*` | Container resource requests/limits and restart counts. | `k8s.container.cpu_limit`, `k8s.container.restarts` |
| `k8s.deployment.*`, `k8s.daemonset.*`, `k8s.statefulset.*` | Workload availability and replica metrics. | `k8s.deployment.desired`, `k8s.daemonset.ready_nodes` |
| `k8s.resource_quota.*` | Namespace quota usage and limits. | `k8s.resource_quota.used` |
| `openshift.*` | OpenShift-specific cluster quota metrics. | `openshift.clusterquota.limit` |

Each metric can be turned on or off individually:

```yaml
metrics:
  k8s.container.cpu_limit:
    enabled: false
```

For a full reference list of default and optional metrics, refer to the [contrib documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/k8sclusterreceiver/documentation.md).



## Resource attributes

Telemetry emitted by this receiver includes rich metadata attributes that provide context about where and how the data was collected.

The most common attributes include:

| Attribute | Description | Example |
|------------|--------------|----------|
| `k8s.node.name` | Node name where the pod is scheduled | `gke-prod-node-01` |
| `k8s.pod.name` | Pod name | `nginx-deployment-6c9c57f9d4-8z8xk` |
| `k8s.namespace.name` | Namespace of the resource | `default` |
| `k8s.container.name` | Container name | `nginx` |
| `container.image.name` | Container image name | `nginx` |
| `container.image.tag` | Container image tag | `1.27` |

To turn off specific attributes:

```yaml
resource_attributes:
  container.id:
    enabled: false
```



## Use cases in Elastic Observability

Typical use cases for this receiver in Elastic Observability include:

- Cluster health monitoring - view node readiness, allocatable capacity, and workload distribution.  
- Workload lifecycle tracking - track deployments, jobs, and cronjobs through phases and conditions.  
- Resource quota enforcement - observe namespace or cluster-level resource quotas and usage trends.  
- OpenShift observability - when `distribution: openshift` is set, collect OpenShift-specific quota metrics.

Combine with the `k8sobjects` receiver for detailed resource inventory data.



## RBAC permissions

The receiver requires access to Kubernetes resources controlled by RBAC (Role-Based Access Control). When using `serviceAccount` authentication, assign a `ClusterRole` and `ClusterRoleBinding` that grant `get`, `list`, and `watch` permissions.

If using the `namespaces` setting to scope access, create `Role` and `RoleBinding` resources per namespace.  

:::{note}
Creating `Role` and `RoleBinding` resources per namespace limits visibility into cluster-wide resources like Nodes and ClusterResourceQuotas.
:::

See [contrib RBAC examples](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver#rbac).



## Caveats and limitations

The following considerations apply when using the `k8s_cluster` receiver in the {{edot}} Collector. These behaviors originate from the contrib OpenTelemetry implementation and also apply to other distributions:

- Only one active `k8s_cluster` instance should run per cluster. Use `k8s_leader_elector` extension for high availability (HA).
- Restricting namespaces turns off some cluster-level metrics.  
- Contrib metric stability: development (logs) and beta (metrics).  
- Requires direct access to the Kubernetes API and appropriate RBAC permissions.



## Resources

- [Contrib `k8s_cluster` receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver)  
- [Kubernetes environments](opentelemetry://reference/architecture/k8s.md)