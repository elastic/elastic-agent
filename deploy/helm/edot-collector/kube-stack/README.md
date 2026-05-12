## Kube-stack Helm Chart

More detailed documentation can be found [here](https://github.com/elastic/opentelemetry/blob/main/docs/kubernetes/operator/README.md).

The [kube-stack Helm Chart](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-kube-stack#readme) is used to manage the installation of the OpenTelemetry operator (including its CRDs) and to configure a suite of EDOT collectors, which instrument various Kubernetes components to enable comprehensive observability and monitoring.

The chart is installed with the provided default [`values.yaml`](./values.yaml) file, which can be customized when needed.

### DaemonSet collectors

The OpenTelemetry components deployed within the DaemonSet EDOT collectors are responsible for observing specific signals from each node. To ensure complete data collection, these components must be deployed on every node in the cluster. Failing to do so results in partial and potentially incomplete data.

The DaemonSet collectors handle the following data:

- Host Metrics: Collects host metrics specific to each node by using the [hostmetrics receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md).
- Kubernetes Metrics: Captures metrics related to the Kubernetes infrastructure on each node by using the [kubeletstats receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/kubeletstatsreceiver/README.md).
- Logs: Uses the [File Log Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/filelogreceiver#readme) to gather logs from all Pods running on the respective node.
- OTLP Traces: Uses the [OTLP Receiver](https://github.com/open-telemetry/opentelemetry-collector/blob/main/receiver/otlpreceiver#readme), which configures both HTTP and gRPC endpoints on the node to receive OTLP trace data.

### Deployment collectors

#### Cluster

The OpenTelemetry components deployed within a Deployment collector focus on gathering data at the cluster level rather than at individual nodes. A Deployment instance of the collector operates as a standalone component, unlike DaemonSet collector instances, which are deployed on every node.

The Cluster Deployment collector handles the following data:

- Kubernetes Events: Monitors and collects events occurring across the entire Kubernetes cluster by using the [Kubernetes Events Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8seventsreceiver#readme).
- Cluster Metrics: Captures metrics that provide insights into the overall health and performance of the Kubernetes cluster by using the [Kubernetes Cluster Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/k8sclusterreceiver#readme).

#### Gateway

The OpenTelemetry components deployed within the `Gateway` Deployment collectors focus on processing and exporting OTLP data to Elasticsearch. Processing components include:

- [Elastic APM processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticapmprocessor): Enriches traces with Elastic-specific requirements and uses `opentelemetry-lib` to perform the actual enrichments.
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

```bash
$ kubectl create namespace opentelemetry-operator-system
```

2. Create a secret in Kubernetes with the following command:

   ```bash
   kubectl create -n opentelemetry-operator-system secret generic elastic-secret-otel \
     --from-literal=elastic_endpoint='YOUR_ELASTICSEARCH_ENDPOINT' \
     --from-literal=elastic_api_key='YOUR_ELASTICSEARCH_API_KEY'
   ```

   Replace:

   - `YOUR_ELASTICSEARCH_ENDPOINT`: your Elasticsearch endpoint (*with* `https://` prefix example: `https://1234567.us-west2.gcp.elastic-cloud.com:443`).
   - `YOUR_ELASTICSEARCH_API_KEY`: your Elasticsearch API Key

3. For Amazon EKS only, configure IAM permissions. This step is not required for GKE or other Kubernetes environments.

   1. **Create an IAM policy**:

      - Go to AWS IAM console
      - Create a new policy with the following JSON:

      ```json
      {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Effect": "Allow",
            "Action": [
              "ec2:DescribeInstances",
              "ec2:DescribeTags",
              "tag:GetResources"
            ],
            "Resource": "*"
          }
        ]
      }
      ```

      - Name the policy `EKSElasticAgentPolicy`

   2. **Create an IAM role for service account**:

      ```bash
      eksctl create iamserviceaccount \
        --name elastic-agent \
        --namespace elastic-agent \
        --cluster your-cluster-name \
        --attach-policy-arn arn:aws:iam::aws:policy/AmazonEKSClusterPolicy \
        --attach-policy-arn arn:aws:iam::YOUR_AWS_ACCOUNT_ID:policy/EKSElasticAgentPolicy \
        --approve \
        --override-existing-serviceaccounts
      ```

4. Execute the following commands to deploy the Helm Chart.

```bash
$ helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
$ helm repo update
$ helm upgrade --install --namespace opentelemetry-operator-system opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack --values ./values.yaml --version 0.3.3
```

> [!NOTE]
> Refer to the [compatibility matrix](https://github.com/elastic/opentelemetry/blob/main/docs/kubernetes/operator/README.md#compatibility-matrix) for a complete list of available manifests and associated helm chart versions.
