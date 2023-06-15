# Elastic Agent Manifests in order to support Kube-State-Metrics Sharding

Kube-state-metrics (KSM) project provides [horizontal sharding](https://github.com/kubernetes/kube-state-metrics#horizontal-sharding) in order to support large kubernetes deployments. As Elastic-Agent collection from kube-state-metrics is proved to be resource intensive, we need to be able to support such horizontal scaling scenarios with our configuration. This doc aims to provide information on how to configure Elastic Agent with KSM horizontally sharded.

*IMPORTANT*: Please review the relevant [Scaling Elastic Agent in Kubernetes document](https://www.elastic.co/guide/en/fleet/master/scaling-on-kubernetes.html) before you continue. The documentation explains in more details why and how we concluded in the below configurations.

## Kube State Metrics Configuration

Deploy kube-state metrics with autosharding (by default number of replicas is 2)

```bash
git clone https://github.com/kubernetes/kube-state-metrics
cd kube-state-metrics/examples/autosharding 
kubectl apply -k .
```

The default dns entries for to access created ksm pods are (assuming namespace of installation of KSM remains default: `kube-system`):

- **KSM Shard01:** kube-state-metrics-0.kube-state-metrics.kube-system.svc.cluster.local:8080
- **KSM Shard02:** kube-state-metrics-1.kube-state-metrics.kube-system.svc.cluster.local:8080

## Installation methods of elastic-agent

This document suggests **the 4 alternative configuration methods** to deploy elastic-agent in big scale Kubernetes clusters with KSM in sharding configuration. In general, we split the agent installation. We use a `daemonset Leader Elastic Agent` that collects both node-wide metrics and Kubernetes API Server metrics and `deployment (or statefuleset) Elastic Agents` that collect metrics from the different KSM Shard endpoints.

1. `Elastic Agent as side-container with KSM Sharded pods`. The Elastic Agent will be installed as `Statefulset` with `hostNetwork:false` and will be a side container of Kube-state-metrics. Meaning that KSM and Elastic Agent will share the same localhost network to communicate.
2. With `hostNetwork:false` for non-leader Elastic Agent deployments that will collect from KSM Shards. In this configuration Elastic Agent will be installed as deployments and we will need one deployment for every KSM Shard collection endpoint. An additional Elastic Agent Leader wi
3. With `taint/tolerations` to isolate the Elastic Agent `Daemonset` pods from rest of Elastic Agent `Deployments`. Tolerations configuration is the mean to exclude Daemonset pods from nodes where the Elastic Agent KSM pods run. So the Elastic Agent Daemonset pods will run only on those nodes where no Elastic Agents that collect KSM run.

Each configuration includes specific pros and cons and users may choose what best matches their needs.

| Installation Method  | No of Policies  | Who can Use it  | Notes |
|---|---|---|---|
| Elastic Agent `Statefulset + KSM as Side Container`  | 2 (1 Policy for Leader Daemonset + 1 Policy for all KSM Elastic Agents) | Suggested for K8s clusters more than 2K pods. When latency problems occur (see relevant [Latency section](https://github.com/elastic/ingest-docs/blob/325a46d475f4446199955c6acbf8f372535ed57b/docs/en/ingest-management/elastic-agent/scaling-on-kubernetes.asciidoc))  | Easiest to configure. Suitable for automation scenarios  |
| Elastic Agent Deployment with `hostNetwork:false` | 1 Policy for Leader Daemonset + N Policies for each N KSM shards.)  |  Same as above, for k8s clusters more than 2k pods | More manual steps needed comparing to previous method. The KSM and Elastic Agents are in different pods  |
| Elastic Agents with taint/tolerations  | 1 Policy for Leader Daemonset + N Policies for each N KSM shards.)  | When users need to specify the nodes of Elastic Agent  | More complex method but gives more scheduling abilities to users |

The Kubernetes observability is based on [kubernetes integration](https://docs.elastic.co/en/integrations/kubernetes), which is fetching metrics from several components:

- **Per node:**
  - kubelet
  - controller-manager
  - scheduler
  - proxy
- **Cluster Wide (i.e. correspond to the whole cluster):**
  - kube-state-metrics
  - apiserver

The Elastic Agent manifest is deployed by default as daemonset. That said, each elastic agent by default is being deployed on every node of kubernetes cluster.

Additionally by default, one agent is elected as [**leader**](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-standalone-kubernetes.yaml#L32) and this will be responsible for also collecting the cluster wide metrics.

So let us discuss each alternative configuration method above. We will provide relevant [manifests](./manifests) to assist installation. We will describe the managed agent installation scenario (for simplicity we would not mention standalone scenarios, but relevant [manifests](./manifests) will be provided for both scenarios)

### 1. Elastic Agent with HostNetwork:false and side container of KSM

For this installation, users need to configure the two following agent policies.

*Note*: The mount point of /var/lib/elastic-agent-managed/kube-system/state to [store elastic-agent state](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-managed-kubernetes.yaml#L104), creates conflicts between Leader Elastic Agent and KSM Agents. This is the reason that it should be removed in `HostNetwork:false` scenarios.

**Agent policies:**

- One main policy where the KSM will be disabled. This policy will be used from the daemonset Elastic Agent manifest
- One policy with only KSM enabled.
  - Leader Election will be disabled
  - KSM Url endpoint: `localhost:8080`

**Manifest Installation:**

Follow steps of [KSM Autosharding with Side Container](./manifests/kustomize-autosharding/README.md)

**Pros/Cons**:

- [+] Simplicity. Only one policy is required for all KSM shards. Easy solution to scale
- [+] Localhost communication between KSM and Elastic Agent
- [-] Users need to patch the Statefuleset of KSM in order to create Elastic Agent as side container

### 2. HostNetwork:false Installation for non-leader Elastic Agent deployments

For this installation, users need to configure the two following agent policies.

*Note*: The mount point of /var/lib/elastic-agent-managed/kube-system/state to [store elastic-agent state](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-managed-kubernetes.yaml#L104), creates conflicts between Leader Elastic Agent and KSM Agents. This is the reason that it should be removed in `HostNetwork:false` scenarios

**Agent policies:**

- Leader Daemonset Policy:
Keep enabled all the default datasets
![daemonset policy](./images/ksm01.png)
- Only change the kube-state-metrics endpoint url to point to `kube-state-metrics-0`
![daemonset policy](./images/ksm-ksm01.png)

- Deployment policy for rest of shards. **Repeat and create same policies for each shard you have created with KSM installation**
Disable all the default datasets except KSM
![daemonset policy](./images/ksm02.png)
- Change the kube-state-metrics endpoint url to point to `kube-state-metrics-1`
![daemonset policy](./images/ksm-ksm02.png)

**Manifest Installation:**

Deploy following manifests:

```bash
 kubectl apply -f elastic-agent-managed-daemonset-ksm-0.yaml
 kubectl apply -f elastic-agent-managed-deployment-ksm-1.yaml
```

> **Note**: Above manifests exist under [manifests/hostnetwork](./manifests/hostnetwork) folder

> **Note**: Make sure that `hostNetwork:false` in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/kubernetes_deployment_ksm-1.yaml#40).

**Pros/Cons**:

- [+] Simplicity
- [-] You can not prevent execution of deployments in nodes where agents already running.

### 3. Tolerations Installation

**Agent Policies:**
For this installation, users need to configure the following agent policies:

- Daemonset resources will include the leader ksm and apiserver.
  ![Deployment policy in tolerations config](./images/tolerationsksm0.png)
  
  ![Deployment policy in tolerations config](./images/tolerationsdaemonset.png)

- **One Agent Policy per KSM shard URL endpoint needs to be assigned to a different deployment**
  - a) Leader Election should be disabled in all deployments

**Manifest Installation:**

1. Revert any changes from previous scenarios. Make sure that `hostNetwork:true` in [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/kubernetes_deployment_ksm-1.yaml#40). This option is not needed anymore and can be reverted in this scenario. 
2. Uncomment the following `toleration` in manifest [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/tolerations/elastic-agent-managed-deployment-ksm-1.yaml). Only the deployments need to include tolerations

   ```bash
    tolerations:
        - key: "deployment"
            operator: "Equal"
            value: "yes"
            effect: "NoSchedule"
   ```

3. Taint a specific node that you want to exclude from being assigned to daemonset pods

    ```bash
    kubectl taint nodes gke-kubernetes-scale-kubernetes-scale-0f73d58f-4rt9 deployment=yes:NoSchedule
    ```

4. Edit [elastic-agent-managed-deployment-ksm-1.yaml](./manifests/tolerations/elastic-agent-managed-deployment-ksm-1.yaml) and specify the node where you need to install it.

```yaml
spec: 
  nodeName: gke-kubernetes-scale-kubernetes-scale-0f73d58f-8cz4
```

5. Deploy your manifests:

    ```bash
    kubectl apply -f elastic-agent-managed-daemonset-ksm-0.yaml
    kubectl apply -f elastic-agent-managed-deployment-ksm-1.yaml
    ```

```bash
 kubectl get pods -n kube-system| grep elastic
elastic-agent-2jw86                                              1/1     Running   0          4m33s
elastic-agent-56cfc5759-7bmz7                                    1/1     Running   0          4m11s     < This is the deployment Agent
elastic-agent-65f59                                              1/1     Running   0          4m33s
elastic-agent-8j9t6                                              1/1     Running   0          4m33s
elastic-agent-b5mgk                                              1/1     Running   0          4m33s
elastic-agent-fn5tt                                              1/1     Running   0          4m33s
elastic-agent-g4m92                                              1/1     Running   0          4m33s
elastic-agent-h4wbc                                              1/1     Running   0          4m33s

kubectl get pod -n kube-system elastic-agent-56cfc5759-7bmz7 -o jsonpath='{.spec.nodeName}'
gke-kubernetes-scale-kubernetes-scale-0f73d58f-8cz4
```

> **Note**: Above manifests exist under [manifests/tolerations](./manifests/tolerations) folder


**Pros/Cons**:

- [+] You *can* prevent execution of deployments in nodes where agents already running
- [+] Gives possibilities to users to configure the pod scheduling exactly as they need
- [-] More complex method and requires manual steps
