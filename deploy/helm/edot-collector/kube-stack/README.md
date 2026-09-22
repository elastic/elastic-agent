## Kube-stack Helm Chart

**More detailed documentation can be found [here](https://github.com/open-telemetry/opentelemetry-operator/blob/main/README.md).**

The [kube-stack Helm Chart](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-kube-stack#readme) is used to manage the installation of the OpenTelemetry operator (including its CRDs) and to configure a suite of EDOT collectors, which instrument various Kubernetes components to enable comprehensive observability and monitoring.

The chart is installed with a provided default [`values.yaml`](./values.yaml) file that can be customized when needed.

### DaemonSet collectors

The OpenTelemetry components deployed within the DaemonSet EDOT collectors are responsible for observing specific signals from each node. To ensure complete data collection, these components must be deployed on every node in the cluster. Failing to do so will result in partial and potentially incomplete data.

The DaemonSet collectors handle the following data:

- Host Metrics: Collects host metrics specific to each node, utilizing the [hostmetrics receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md)
- Kubernetes Metrics: Captures metrics related to the Kubernetes infrastructure on each node, utlilizing [kubeletstats](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kubeletstatsreceiver/README.md) receiver
- Logs: Utilizes [File Log Receiver receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver#readme) to gather logs from all Pods running on the respective node.
- OTLP Traces: Utilizes [OTLP Receiver]( https://github.com/open-telemetry/opentelemetry-collector/blob/main/receiver/otlpreceiver#readme) which configures both HTTP and GRPC endpoints on the node to receive OTLP trace data.

### Deployment collectors

#### Cluster

The OpenTelemetry components deployed within a Deployment collector focus on gathering data at the cluster level rather than at individual nodes.  A Deployment instance of the collector operates as a standalone (unlike DaemonSet collector instances, which are deployed on every node)

The Cluster Deployment collector handles the following data:

- Kubernetes Events: Monitors and collects events occurring across the entire Kubernetes cluster, utilizing [Kubernetes Events Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8seventsreceiver#readme).
- Cluster Metrics: Captures metrics that provide insights into the overall health and performance of the Kubernetes cluster, utilizing [Kubernetes Cluster Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver#readme).

#### Gateway

The OpenTelemetry components deployed within the `Gateway` Deployment collectors focus on processing and exporting OTLP data to Elasticsearch. Processing components:

- [Elastic APM processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticapmprocessor): The processor enriches traces with elastic specific requirements. It uses opentelemetry-lib to perform the actual enrichments.
- DEPRECATED: [Elastic Infra Metrics processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor): The Elastic Infra Metrics Processor is used to bridge the gap between OTEL and Elastic Infra Metrics. This processor is deprecated and will be removed in 9.2.0.
- [Elastic APM connector](https://github.com/elastic/opentelemetry-collector-components/tree/main/connector/elasticapmconnector): The Elastic APM connector produces aggregated Elastic APM-specific metrics from all telemetry signals.

### Auto-instrumentation

The Helm Chart is configured to enable zero-code instrumentation using the [Operator's Instrumentation resource](https://github.com/open-telemetry/opentelemetry-operator/?tab=readme-ov-file#opentelemetry-auto-instrumentation-injection) for the following programming languages:

- Go
- Java
- Node.js
- Python
- .NET


### Installation

1. Create the `opentelemetry-operator-system` Kubernetes namespace:
```
$ kubectl create namespace opentelemetry-operator-system
```

2. Create a secret in Kubernetes with the following command.
   ```
   kubectl create -n opentelemetry-operator-system secret generic elastic-secret-otel \
     --from-literal=elastic_endpoint='YOUR_ELASTICSEARCH_ENDPOINT' \
     --from-literal=elastic_api_key='YOUR_ELASTICSEARCH_API_KEY'
   ```
   Don't forget to replace
   - `YOUR_ELASTICSEARCH_ENDPOINT`: your Elasticsearch endpoint (*with* `https://` prefix example: `https://1234567.us-west2.gcp.elastic-cloud.com:443`).
   - `YOUR_ELASTICSEARCH_API_KEY`: your Elasticsearch API Key

3. Execute the following commands to deploy the Helm Chart.

```shell
$ helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
$ helm repo update
$ helm upgrade --install --namespace opentelemetry-operator-system \
  opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack \
    --values ./values.yaml \
    --version 0.16.0
```

#### OpenShift

The [`./openshift/values.yaml`](./openshift/values.yaml) file contains all the configuration that is needed to run the chart on OpenShift. It is applied on top of the default [`values.yaml`](./values.yaml) file.

1. Follow the steps 1 and 2 from the [Installation](#installation) section to create the namespace and the secret.

2. Execute the following commands to deploy the Helm Chart with both values files:

```shell
$ helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
$ helm repo update
$ helm upgrade --install --namespace opentelemetry-operator-system \
  opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack \
    --values ./values.yaml \
    --values ./openshift/values.yaml \
    --version 0.16.0
```

If the OpenTelemetry Operator is already installed through the Operator Lifecycle Manager (OLM), the chart must not install a second operator. Disable the operator and its CRDs with the following command:

```shell
$ helm upgrade --install --namespace opentelemetry-operator-system \
  opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack \
    --values ./values.yaml \
    --values ./openshift/values.yaml \
    --set crds.installOtel=false \
    --set opentelemetry-operator.enabled=false \
    --version 0.16.0
```

### Compatibility

Each OpenTelemetry Operator version supports a specific range of Kubernetes versions and each Helm Chart version installs a specific Operator version. Use a chart version that matches the Kubernetes version of your cluster:

> [!NOTE]
> Refer to the [compatibility matrix](https://github.com/open-telemetry/opentelemetry-operator/blob/main/docs/getting-started/compatibility.md#compatibility-matrix) for a complete list of available manifests and associated helm chart versions.
