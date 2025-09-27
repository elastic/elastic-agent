---
navigation_title: Metrics collection
description: Learn how to configure and customize metrics collection through the Elastic Distribution of OpenTelemetry Collector. 
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

# Configure metrics collection

Learn how to configure and customize metrics collection through the {{edot}} Collector. 

:::{note}
{{es}} Ingest Pipelines are not yet applicable to OTel-native data. Use OTel Collector processing pipelines for pre-processing metrics.
:::

## OTLP metrics

Any application emitting metrics through OpenTelemetry Protocol (OTLP) can forward them to the EDOT Collector using the OTLP receiver. This is the recommended method for collecting application-level telemetry.

The following OTLP receiver configuration turns on both gRPC and HTTP protocols for incoming OTLP traffic:

```yaml
# [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver)
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
```

Configure your application to export metrics using the OTLP protocol, targeting the endpoints provided in the previous example.

## Host metrics

The [hostmetrics receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver) turns on the collection of host-level metrics such as CPU use, memory use, and filesystem stats.

The following configuration collects a standard set of host metrics that aligns with Elastic's Infrastructure dashboards in {{kib}}:

```yaml
hostmetrics:
  collection_interval: 10s
  root_path: /proc # Mounted node's root file system
  scrapers:
    cpu:
      metrics:
        system.cpu.utilization:
          enabled: true
        system.cpu.logical.count:
          enabled: true
    memory:
      metrics:
        system.memory.utilization:
          enabled: true
    network: {}
    processes: {}
    load: {}
    disk: {}
    filesystem:
      exclude_mount_points:
        mount_points:
          - /dev/*
          - /proc/*
          - /sys/*
          - /run/k3s/containerd/*
          - /var/lib/docker/*
          - /var/lib/kubelet/*
          - /snap/*
        match_type: regexp
      exclude_fs_types:
        fs_types:
          - autofs
          - binfmt_misc
          - bpf
          - cgroup2
          - configfs
          - debugfs
          - devpts
          - devtmpfs
          - fusectl
          - hugetlbfs
          - iso9660
          - mqueue
          - nsfs
          - overlay
          - proc
          - procfs
          - pstore
          - rpc_pipefs
          - securityfs
          - selinuxfs
          - squashfs
          - sysfs
          - tracefs
        match_type: strict
```

You must grant access to the `/proc` filesystem to the receiver by running the Collector with privileged access and mounting /proc and /sys appropriately. Refer to the hostmetrics container use [guide](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver#collecting-host-metrics-from-inside-a-container-linux-only) (Linux only).

Turning on the process scraper might significantly increase the volume of scraped metrics, potentially impacting performance. Refer to the contrib issue [#39423](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/39423) for discussion.

To ensure compatibility with {{kib}}'s Infrastructure dashboards, include the [elasticinframetrics processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor) in your pipeline:

 ```yaml
      service:
        pipelines:
          metrics/infra:
            receivers:
              - hostmetrics
            processors:
              - elasticinframetrics
 ```

### Process metrics

:::{include} ../_snippets/process-config.md
:::

## Kubernetes metrics

You can collect Kubernetes metrics using multiple receivers depending on the type and source of the metrics. Each receiver might require specific Kubernetes permissions and require a deployment as DaemonSets or singletons.

As with host metrics, use the [elasticinframetrics processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor) to ensure metrics align with the {{kib}} Infrastructure inventory.

### Kubelet metrics

The [kubeletstats](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver) receiver collects resource usage stats directly from the Kubelet's /stats/summary endpoint. Stats include pod-level and node-level metrics.

```yaml
kubeletstats:
  auth_type: serviceAccount # Authentication mechanism with the Kubelet endpoint, refer to: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver#configuration
  collection_interval: 20s
  endpoint: ${env:OTEL_K8S_NODE_NAME}:10250
  node: '${env:OTEL_K8S_NODE_NAME}'
  # Required to work for all CSPs without an issue
  insecure_skip_verify: true
  k8s_api_config:
    auth_type: serviceAccount
  metrics:
    k8s.pod.memory.node.utilization:
      enabled: true
    k8s.pod.cpu.node.utilization:
      enabled: true
    k8s.container.cpu_limit_utilization:
      enabled: true
    k8s.pod.cpu_limit_utilization:
      enabled: true
    k8s.container.cpu_request_utilization:
      enabled: true
    k8s.container.memory_limit_utilization:
      enabled: true
    k8s.pod.memory_limit_utilization:
      enabled: true
    k8s.container.memory_request_utilization:
      enabled: true
    k8s.node.uptime:
      enabled: true
    k8s.node.cpu.usage:
      enabled: true
    k8s.pod.cpu.usage:
      enabled: true
  extra_metadata_labels:
    - container.id
```

To capture stats from every node in the cluster, deploy the Collector with the kubeletstats receiver as a DaemonSet.

### Cluster metrics

The [k8sclusterreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver) gathers metrics and entity events directly from the Kubernetes API server. It captures cluster-wide resources like nodes, deployments, pods, and more.

```yaml
k8s_cluster:
  auth_type: serviceAccount # Determines how to authenticate to the K8s API server. This can be one of none (for no auth), serviceAccount (to use the standard service account token provided to the agent pod), or kubeConfig to use credentials from ~/.kube/config.
  node_conditions_to_report:
    - Ready
    - MemoryPressure
  allocatable_types_to_report:
    - cpu
    - memory
  metrics:
    k8s.pod.status_reason:
      enabled: true
  resource_attributes:
    k8s.kubelet.version:
      enabled: true
    os.description:
      enabled: true
    os.type:
      enabled: true
    k8s.container.status.last_terminated_reason:
      enabled: true
```

Run a single instance of this receiver, for example as a Deployment, with sufficient permissions to access the K8s API server.

## Other metrics

The EDOT Collector supports a wide range of metrics receivers for popular software systems, including:

 - Redis ([redisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/redisreceiver)): Retrieve Redis INFO data from a single Redis instance.

 - JMX-based applications ([jmxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/jmxreceiver)): Open a child Java process running the JMX Metric Gatherer configured with your specified JMX connection information and target Groovy script. It then reports metrics to an implicitly created OTLP receiver.

 - Prometheus scrape targets ([prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver)): Receives metric data in [Prometheus](https://prometheus.io/) format.

 - Kafka ([kafkareceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kafkareceiver)): Receives telemetry data from Kafka, with configurable topics and encodings.

For a full list of supported receivers, see the EDOT Collector components [reference](/reference/edot-collector/components.md).
