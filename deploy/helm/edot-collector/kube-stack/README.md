## Kube-stack Helm Chart

**More detailed documentation can be found [here](https://github.com/elastic/opentelemetry/blob/main/docs/kubernetes/operator/README.md).**

The [kube-stack Helm Chart](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-kube-stack#readme) is used to manage the installation of the OpenTelemetry operator (including its CRDs) and to configure a suite of EDOT collectors, which instrument various Kubernetes components to enable comprehensive observability and monitoring.

The chart is installed with a provided default [`values.yaml`](./values.yaml) file that can be customized when needed.

### DaemonSet collectors

The OpenTelemetry components deployed within the DaemonSet EDOT collectors are responsible for observing specific signals from each node. To ensure complete data collection, these components must be deployed on every node in the cluster. Failing to do so will result in partial and potentially incomplete data.

The DaemonSet collectors handle the following data:

- Host Metrics: Collects host metrics specific to each node, utilizing the [hostmetrics receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md)
- Kubernetes Metrics: Captures metrics related to the Kubernetes infrastructure on each node, utlilizing [kubeletstats](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kubeletstatsreceiver/README.md) receiver
- Logs: Utilizes [File Log Receiver receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver#readme) to gather logs from all Pods running on the respective node.
- OTLP Traces: Utilizes [OTLP Receiver]( https://github.com/open-telemetry/opentelemetry-collector/blob/main/receiver/otlpreceiver#readme) which configures both HTTP and GRPC endpoints on the node to receive OTLP trace data.

### Deployment collector

The OpenTelemetry components deployed within a Deployment collector focus on gathering data at the cluster level rather than at individual nodes.  A Deployment instance of the collector operates as a standalone (unlike DaemonSet collector instances, which are deployed on every node)

The Deployment collector handles the following data:

- Kubernetes Events: Monitors and collects events occurring across the entire Kubernetes cluster, utilizing [k8sobject](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sobjectsreceiver) receiver
- Cluster Metrics: Captures metrics that provide insights into the overall health and performance of the Kubernetes cluster, utilizing [k8s_cluster](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver) receiver

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

```
$ helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
$ helm repo update
$ helm upgrade --install --namespace opentelemetry-operator-system opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack --values ./values.yaml --version 0.3.0
```
