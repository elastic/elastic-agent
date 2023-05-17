# Elastic Agent Manifests in order to support Kube-State-Metrics Sharding

Kube-state-metrics (KSM) library supports horizontal sharding (more [information](https://github.com/kubernetes/kube-state-metrics#horizontal-sharding)). As Elastic-Agent collection from kube-state-metrics is proved to be resource intensive, we need to be able to support such horizontal scaling scenarios

## Kube State Metrics Configuration

Deploy kube-state metrics with autosharding (by default number of replicas is 2)

```bash
git clone https://github.com/kubernetes/kube-state-metrics
cd kube-state-metrics/examples/autosharding 
kubectl apply -k .
```

The default dns entries for to access created ksm pods are (assuming namespace of installation of ksm remains default: `kube-system` ):

- **KSM Shard01:** kube-state-metrics-0.kube-state-metrics.kube-system.svc.cluster.local:8080
- **KSM Shard02:** kube-state-metrics-1.kube-state-metrics.kube-system.svc.cluster.local:8080

## Installation methods of elastic-agent

This document suggests 3 different ways to deploy elastic-agent in big scale Kubernetes clusters with KSM in sharding configuration:

1. With `hostNetwork:false` for non-leader deployments of KSM shards
2. With `podAntiAffinity` to isolate the daemonset pods from rest of deployments
3. With `taint/tolerations` to isolate the daemonset pods from rest of deployments

Each configuration includes specific pros and cons and user needs to choose what matches best their needs.

The Kubernetes observability is based on https://docs.elastic.co/en/integrations/kubernetes[kubernetes integration], which is fetching metrics from several components:

- **Per node:**
  - kubelet
  - controller-manager
  - scheduler
  - proxy
- **Cluster Wide (i.e. correspond to the whole cluster):**
  - kube-state-metrics
  - apiserver

The Elastic Agent manifest is deployed by default as daemonset. That said, each elastic agent by default is being deployed on every node of kubernetes cluster.

Additionally by default, one agent is elected as [**leader**](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L32) and this will be responsible for also collecting the cluster wide metrics. So let us discuss each configuration method above. We will provide relevant [manifests](./manifests) to assist installation. We will describe the managed agent installation scenario (for simplicity we would not mention standalone scenarios, but relevant [manifests](./manifests) will be provided for both scenarios)

### HostNetwork:false Installation

For this installation, users need to configure the two following agent policies : 

- Leader Daemonset Policy:
Keep enabled all the default datasets
![daemonset policy](./images/ksm01.png)
Only change the kube-state-metrics endpoint url to point to `kube-state-metrics-0`
![daemonset policy](./images/ksm-ksm01.png)

- Deployment policy for rest of shards. **Repeat and create same policies for each shard you have created with KSM installation**
Disable all the default datasets except KSM
![daemonset policy](./images/ksm02.png)
Only change the kube-state-metrics endpoint url to point to `kube-state-metrics-1`
![daemonset policy](./images/ksm-ksm02.png)

Deploy following manifests:

```bash
 kubectl apply -f elastic-agent-managed-daemonset-ksm-0.yaml
 kubectl apply -f elastic-agent-managed-deployment-ksm-1.yaml
```

> **Note**: Above manifests exist under [manifests]((./manifests) folder)

> **Note**: Make sure that `hostNetwork:false` in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/kubernetes_deployment_ksm-1.yaml#40)

**Pros/Cons**:
[+] Simplicity
[-] You can not prevent execution of deployments in nodes where agents already running.

### PodAntiAffinity Installation

For this installation, users need to configure the same agent policies as described in previous scenario.

1. Make sure that `hostNetwork:true` in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/kubernetes_deployment_ksm-1.yaml#40). This option is not needed anymore and can be reverted in this scenario
2. Uncoment the following `affinity` block in both manifests [elastic-agent-managed-daemonset-ksm-0.yaml](./manifests/elastic-agent-managed-daemonset-ksm-0.yaml), [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/elastic-agent-managed-deployment-ksm-1.yaml)
   ```bash
    affinity:
        podAntiAffinity:  
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:                            
              - key: app
                operator: In
                values:                          
                  - "elastic-agent"
            topologyKey: "kubernetes.io/hostname"
   ```

The above configuration ensures that no more than one pod with `label="elastic-agent"` will be executed in each node

**Pros/Cons**:
[+] You **can* prevent execution of deployments in nodes where agents already running.
[-] More complex than first method
[-] It displays scheduled daemonset pods in state `Pending` where antiaffinity is triggered.


### Tolerations Installation

For this installation, users need to configure the same agent policies as described in first scenario.

1. Revert any changes from previous scenarios. Make sure that `hostNetwork:true` in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/kubernetes_deployment_ksm-1.yaml#40). This option is not needed anymore and can be reverted in this scenario. Also verify that  `affinity` block is commented. 
2. Uncoment the following `toleration` in  manifest[elastic-agent-managed-daemonset-ksm-0.yaml](./manifests/elastic-agent-managed-daemonset-ksm-0.yaml)
   ```bash
    tolerations:
        - key: "sharding"
            operator: "Equal"
            value: "yes"
            effect: "NoExecute"
   ```

3. Taint a specific node that you want to exclude from being assigned to daemonset pods

```bash
 kubectl taint nodes gke-kubernetes-scale-kubernetes-scale-0f73d58f-4rt9 deployment=yes:NoExecute-
```

4. Deploy your daemonsets:

```bash
 kubectl apply -f elastic-agent-managed-daemonset-ksm-0.yaml
```

5. Edit Specify the spec.nodeName where your deployments need to be assigned in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/elastic-agent-managed-deployment-ksm-1.yaml)

6. Deploy your deployments:

```bash
 kubectl apply -f elastic-agent-managed-deployment-ksm-1.yaml
```
