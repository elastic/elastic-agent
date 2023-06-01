# Scaling Testing for Elastic Agent with Kubernetes Integration

This document specifies the methodology followed to perform scaling tests for our Kubernetes Integration solution.
The Kubernetes Observability journey comprises from the following distinct phases:

- Exposure of metrics by Kubernetes
- Collection of metrics in Kubernetes
- Ingestion of Kubernetes metrics into Elasticsearch
- Query performance of Kubernetes metrics held in ES (raw and aggregated evaluation of components that affect Dashboard and Visualisation experience)

*Important Notes:*

- All our tests have been conducted in GKE
- The [tool used](https://github.com/elastic/k8s-integration-infra/tree/cloudnative/scripts/stress_test) to automate the creation of Application Pods that produce metrics. This tool creates nginx pods with minimal cpu/memory consumption.
- The Scaling tests focus only on metrics. No testing regarding log collection has been performed

**Precondition:**

- K8S cluster:
  - Zone: us-central1-c
  - Version: >1.24.9-gke.2000
  - Autoscaling: off
  - Machine type: e2-standard-4
  - kube-state-metrics deployed
  
  Number of nodes:
|===
| No of Pods in K8s Cluster | No of Nodes |  
| 1000 | 11  
| 3000 | 18
| 5000 | 46  
| 10000 | 99
|===

ESS cluster:

- Production | us-west2 region
- Stack: Tests conducted with 8.6.2, 8.7.x and 8.8.0 with TSDB
- Elasticsearch: 5.63 TB storage | 128 GB RAM | 32 vCPU
- Kibana: 8 GB RAM | Up to 8 vCPU
- Integrations Server: 8 GB RAM | Up to 8 vCPU
- Kubernetes integration >=v1.31.2

1. Install Elastic Agent on the k8s cluster as DaemonSet using the Kubernetes manifest (get the manifest from the Fleet page of your ESS cluster). Make sure agent enrollment is confirmed before proceeding with next steps.
2. Add Kubernetes integration to a policy that in use by k8s agents.
3. Deploy **10000** pods using [stress_test_k8s script](https://github.com/elastic/k8s-integration-infra#put-load-on-the-cluster).
`./stress_test_k8s -kubeconfig=/home/andrei_bialenik/.kube/config -deployments=10 -namespaces=1000 -podlabels=4 -podannotations=4`
4. Ensure all pods are created

```bash
kubectl get pods -A | grep -i running | wc -l
kubectl get pods -A | grep -iv running | wc -l

```

5. Ingest data for at least 2 hours. Leave the Application pods
6. Request the count of kube-state metrics from the last 15 minutes / 2 hours in Kibana Dev Tools by running the following query:

```
GET /metrics-kubernetes.state_pod-default/_count
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp":{
              "gte": "2023-04-05T15:30:00.000Z",
              "lt" : "2023-04-05T15:45:00.000Z"
            }
          }
        },
        {
          "regexp": {
            "kubernetes.pod.name": "demo-deployment-.*"
          }
        }
      ]
    }
  }
}
```