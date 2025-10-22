---
navigation_title: Kubernetes objects receiver
description: The Kubernetes objects receiver is an OpenTelemetry Collector component that collects Kubernetes API objects and events for Elastic Observability through the EDOT Collector.
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

# Kubernetes objects receiver

The Kubernetes objects receiver (`k8sobjects`) is a core component of the {{edot}} (EDOT) Collector. It collects Kubernetes API objects, such as events, pods, and namespaces, and emits them as log signals for Elastic Observability.

For full contrib details, refer to the [OpenTelemetry `k8sobjects` receiver documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver).


## How it works

The receiver connects to the Kubernetes API server and collects Kubernetes resources as logs. The receiver supports two collection modes: 

* `pull`: Periodically lists Kubernetes objects at fixed intervals.
* `watch`: Streams real-time updates from the API server as objects are created, modified, or deleted.

Typical use cases include:

* Collecting Kubernetes events (`events.k8s.io` API group) for cluster monitoring and alerting.
* Capturing other objects such as pods, deployments, or configmaps for audit and change tracking.
* Enabling correlation between Kubernetes events and other telemetry in Elastic Observability to link operational changes with application-level telemetry.


## Get started

You can start collecting Kubernetes objects and events with just a few configuration steps.

### Basic configuration

The following example shows the minimal configuration required to start collecting Kubernetes events:

```yaml
receivers:
  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: events
        mode: watch
        group: events.k8s.io
```

Each object on the list defines what resource to collect, from which namespaces, and using which mode (`pull` or `watch`). For example:

```yaml
receivers:
  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: pods
        mode: pull
        interval: 15m
        label_selector: environment=production
      - name: events
        mode: watch
        group: events.k8s.io
        namespaces: [default]
```

### Include in a logs pipeline

Ensure the Kubernetes objects receiver is part of a `logs` pipeline:

```yaml
service:
  pipelines:
    logs:
      receivers: [k8sobjects, filelog]
      processors: [batch]
      exporters: [elasticsearch]
```

### Using the Helm preset

When deploying EDOT Collector using Helm, you can enable the Kubernetes events preset:

```yaml
presets:
  kubernetesEvents:
    enabled: true
```

This preset automatically adds a Kubernetes objects receiver that watches Kubernetes events and sends them to the logs pipeline.


### Mixed configuration

This example demonstrates a more comprehensive setup that combines both collection modes and shows how to integrate the receiver into a complete pipeline:

```yaml
receivers:
  k8sobjects:
    auth_type: serviceAccount
    objects:
      - name: events
        mode: watch
        group: events.k8s.io
      - name: pods
        mode: pull
        interval: 10m

processors:
  batch:

exporters:
  elasticsearch:
    endpoints: ["https://${ELASTICSEARCH_HOST}:443"]
    api_key: "${ELASTIC_API_KEY}"
    mapping_mode: otel
    timeout: 10s

service:
  pipelines:
    logs:
      receivers: [k8sobjects, filelog]
      processors: [batch]
      exporters: [elasticsearch]
```


## Caveats and limitations

Consider the following when deploying the Kubernetes objects receiver:

* Run only one Collector instance with this receiver enabled to avoid duplicate data.
* High-frequency clusters can generate large event bursts. Use filters to reduce noise.
* Use `label_selector` and `field_selector` to target only relevant resources.
* Supports two authentication modes: `serviceAccount` and `kubeConfig`.
* The Collector requires RBAC (Role-Based Access Control) permissions to list or watch the specified resources.
* Custom resources require the corresponding CRDs (Custom Resource Definitions) to be present in the cluster.
* This receiver is marked as **beta** in the contrib repository. APIs and fields may change.


## Resources

For contrib details, refer to the [OpenTelemetry k8sobjectsreceiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver).