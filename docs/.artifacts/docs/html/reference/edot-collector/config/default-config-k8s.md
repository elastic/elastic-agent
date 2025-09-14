---
title: Default configuration of the EDOT Collector (Kubernetes)
description: Default configuration of the EDOT Collector for Kubernetes.
url: https://docs-v3-preview.elastic.dev/reference/edot-collector/config/default-config-k8s
products:
  - Elastic Agent
  - Elastic Cloud Serverless
  - Elastic Distribution of OpenTelemetry Collector
  - Elastic Observability
---

# Default configuration of the EDOT Collector (Kubernetes)

The [Kubernetes setup](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/solutions/observability/get-started/opentelemetry/quickstart/quickstart) uses the OpenTelemetry Operator to automate orchestration of EDOT Collectors:
- [EDOT Collector Cluster](#cluster-collector-pipeline): Collection of cluster metrics.
- [EDOT Collector Daemon](#daemonset-collectors-pipeline): Collection of node metrics, logs and application telemetry.
- [EDOT Collector Gateway](#gateway-collectors-pipeline): Pre-processing, aggregation and ingestion of data into Elastic.

The following `values.yaml` files are used depending on the ingest scenario:
- [Direct ingestion into Elasticsearch](https://github.com/elastic/elastic-agent/blob/main/deploy/helm/edot-collector/kube-stack/values.yaml)
- [Managed OTLP Endpoint](https://github.com/elastic/elastic-agent/blob/main/deploy/helm/edot-collector/kube-stack/managed_otlp/values.yaml)

The following sections describe the default pipelines for the different roles of EDOT collectors in a Kubernetes setup.

## Cluster Collector pipeline

The main purpose of the Cluster collector is to collect Kubernetes cluster-level metrics and events using the [`k8s_cluster`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver) and the [`k8sobjects`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver) receivers.
The [`resource`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor) and [`resourcedetection`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) processors enrich the cluster-level data with corresponding meta information. Data then goes to the Gateway Collector through `OTLP`.

## Daemonset collectors pipeline

The Daemonset collectors gather telemetry associated with corresponding, individual Kubernetes nodes:

### Host metrics and container logs

The [`filelog`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver) and [`hostmetrics`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver) receivers are used to gather container logs and host metrics, respectively. The [`kubeletstats`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/kubeletstatsreceiver) receiver collects additional Kubernetes Node, Pod and Container metrics.
Logs and metrics are batched for better performance ([`batch`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/batchprocessor) processor) and then enriched with meta information using the [`k8sattributes`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/k8sattributesprocessor), [`resourcedetection`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourcedetectionprocessor) and [`resource`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/resourceprocessor) processors.
<important>

  Process metrics are turned off by default to avoid generating a large volume of timeseries data. To turn on process metrics, uncomment or add the following section inside the `hostmetrics` receiver configuration:
  ```yaml
    process:
       mute_process_exe_error: true
       mute_process_io_error: true
       mute_process_user_error: true
       metrics:
          process.threads:
          enabled: true
          process.open_file_descriptors:
          enabled: true
          process.memory.utilization:
          enabled: true
          process.disk.operations:
          enabled: true
  ```
</important>

<note>
  The `from_context: client_metadata` option in the `resource` processor only applies to transport-level metadata. It cannot extract custom application attributes. To propagate such values into your telemetry, set them explicitly in your application code using EDOT SDK instrumentation. For more information, refer to [EDOT Collector doesn’t propagate client metadata](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/troubleshoot/ingest/opentelemetry/edot-collector/metadata).
</note>


### Application telemetry through OTLP from OTel SDKs

The Daemonset collectors also receive the application telemetry from OTel SDKs that instrument services and pods running on corresponding Kubernetes nodes.
The Daemonset collectors receive that data through [`OTLP`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver), batch the data ([`batch`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/batchprocessor) processor) and pass it on to the Gateway Collector through the OTLP exporter.

## Gateway collectors pipeline

The Gateway collectors pipelines differ between the two different deployment use cases, direct ingestion into Elasticsearch and using the [Elastic Cloud Managed OTLP Endpoint](https://docs-v3-preview.elastic.dev/elastic/opentelemetry/tree/main/reference/motlp).

### Direct ingestion into Elasticsearch

In self-managed and Elastic Cloud Hosted Stack deployment use cases, the main purpose of the Gateway Collector is the central enrichment of data before the OpenTelemetry data is being ingested directly into Elasticsearch using the [`elasticsearch`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/elasticsearchexporter) exporter.
The Gateway Collector configuration comprises the pipelines for data enrichment of [application telemetry](/reference/edot-collector/config/default-config-standalone#application-and-traces-collection-pipeline) and [host metrics](/reference/edot-collector/config/default-config-standalone#host-metrics-collection-pipeline). For more details, refer to the linked descriptions of the corresponding standalone use cases.
The [`routing`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/routingconnector) connector separates the infrastructure metrics from other metrics and routes them into the ECS-based pipeline, with ECS-compatibility exporter mode. Other metrics are exported in OTel-native format to Elasticsearch.

### Managed OTLP Endpoint

With the managed OTLP Endpoint, the Gateway Collector configuration pipes all the data from the [`OTLP`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver) receiver through a [`batch`](https://github.com/open-telemetry/opentelemetry-collector/tree/main/processor/batchprocessor) processor before the data is being exported through `OTLP` to the managed endpoint.
With this scenario there's no need to do any Elastic-specific enrichment in your Kubernetes cluster, as all of that happens behind the managed OTLP endpoint.