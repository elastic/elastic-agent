## Kube-stack Helm Chart

More detailed Kubernetes operator documentation is available [here](https://github.com/elastic/opentelemetry/blob/main/docs/kubernetes/operator/README.md).

This directory contains the default `values.yaml` used to deploy the OpenTelemetry `kube-stack` chart with Elastic Distribution of OpenTelemetry (EDOT) collectors. The deployment installs the OpenTelemetry Operator and configures three collector roles:

- `daemon`: a DaemonSet that runs on every node to collect host metrics, kubelet metrics, pod logs, and receive OTLP traffic from instrumented workloads
- `cluster`: a Deployment that collects cluster-wide Kubernetes events and cluster metrics
- `gateway`: a Deployment that receives OTLP data from the other collectors, applies Elastic-specific processing, and exports data to Elasticsearch

The included [`values.yaml`](./values.yaml) has been tested with `opentelemetry-kube-stack` chart version `0.3.3`.

### Default data flow

The default configuration in this directory enables the following telemetry paths:

- Node-level logs from the `filelog` receiver are sent from the `daemon` collector to the `gateway`
- Host and Kubernetes node metrics from `hostmetrics` and `kubeletstats` are sent from the `daemon` collector to the `gateway`
- Cluster metrics and Kubernetes events are collected by the `cluster` collector and forwarded to the `gateway`
- Application OTLP traffic is received by the `daemon` collector on ports `4317` and `4318`, then forwarded to the `gateway`
- The `gateway` collector exports telemetry to Elasticsearch by using credentials from the `elastic-secret-otel` Kubernetes secret

### Auto-instrumentation

The chart enables zero-code instrumentation through the Operator `Instrumentation` resource for these languages:

- Go
- Java
- Node.js
- Python
- .NET

By default, the Operator `Instrumentation` resource exports telemetry to the in-cluster daemon collector service:

- `http://opentelemetry-kube-stack-daemon-collector.opentelemetry-operator-system.svc.cluster.local:4318`

### Prerequisites

- A Kubernetes cluster with permissions to install CRDs
- `kubectl` configured for the target cluster
- Helm 3
- An Elasticsearch endpoint and API key

### EKS-only IAM configuration

If you deploy this chart on Amazon EKS and want AWS metadata enrichment to work correctly, configure IAM permissions before installing the chart.

These AWS-specific steps are not required for GKE or other Kubernetes environments.

1. Create an IAM policy in AWS IAM with the following document:

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

Name the policy `EKSElasticAgentPolicy`.

2. Create an IAM role for the service account:

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

Replace:

- `your-cluster-name` with your EKS cluster name
- `YOUR_AWS_ACCOUNT_ID` with your AWS account ID

### Installation

1. Create the namespace used by the OpenTelemetry Operator:

```bash
kubectl create namespace opentelemetry-operator-system
```

2. Create the secret consumed by the `gateway` collector:

```bash
kubectl create secret generic elastic-secret-otel \
  -n opentelemetry-operator-system \
  --from-literal=elastic_endpoint='YOUR_ELASTICSEARCH_ENDPOINT' \
  --from-literal=elastic_api_key='YOUR_ELASTICSEARCH_API_KEY'
```

Replace:

- `YOUR_ELASTICSEARCH_ENDPOINT` with your Elasticsearch endpoint, including the `https://` prefix, for example `https://1234567.us-west2.gcp.elastic-cloud.com:443`
- `YOUR_ELASTICSEARCH_API_KEY` with an Elasticsearch API key that can ingest observability data

3. Install the upstream chart by using the values file from this directory:

```bash
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update
helm upgrade --install opentelemetry-kube-stack open-telemetry/opentelemetry-kube-stack \
  --namespace opentelemetry-operator-system \
  --create-namespace \
  --values ./values.yaml \
  --version 0.3.3
```

Note: refer to the [compatibility matrix](https://github.com/elastic/opentelemetry/blob/main/docs/kubernetes/operator/README.md#compatibility-matrix) for the supported manifest and chart combinations.

### Verify the installation

After installation, confirm that the Operator and collectors are running:

```bash
kubectl get pods -n opentelemetry-operator-system
kubectl get opentelemetrycollectors -n opentelemetry-operator-system
kubectl get instrumentation -n opentelemetry-operator-system
```

You should see collector resources for `daemon`, `cluster`, and `gateway`, plus the `elastic-instrumentation` resource when auto-instrumentation is enabled.

### Common customizations

- Set `clusterName` in [`values.yaml`](./values.yaml) if your Kubernetes provider does not automatically populate `k8s.cluster.name`
- Disable `instrumentation.enabled` if you do not want Operator-managed auto-instrumentation
- Adjust the `gateway` resource requests and limits for larger clusters or higher ingest volume
- Update collector pipelines in [`values.yaml`](./values.yaml) if you need additional receivers, processors, or exporters
