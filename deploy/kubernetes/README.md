# Beats Kubernetes manifests examples

## Getting started

This is the list of officially supported Elastic Agents, with example manifests to run
them in Kubernetes:

Agent Mode | Description
---- | ----
[Elastic Agent managed](elastic-agent-managed) | Elastic Agent managed by Fleet setup
[Elastic Agent standalone](elastic-agent-standalone) | Standalone Elastic Agent setup

> Note: `kube-state-metrics` (KSM) is not installed as part of the above manifests and needs to be installed from [kube-state-metrics](https://github.com/kubernetes/kube-state-metrics).

## Kustomize Templates

In addition to the above manifests, the list below includes the official [kustomize](https://github.com/kubernetes-sigs/kustomize) templates to run them in Kubernetes:

Agent Scenario | Description
---- | ----
[Elastic Agent managed - Default ](./default/elastic-agent-managed/) | Default Elastic Agent managed by Fleet setup. Kube-state-metrics (KSM) is installed automatically.
[Elastic Agent standalone Default ](./default/elastic-agent-standalone/) | Default Standalone Elastic Agent setup. Kube-state-metrics (KSM) is installed automatically.
[Elastic Agent managed - With KSM in autosharding configuration ](./ksm-autosharding/elastic-agent-managed/) | Elastic Agent managed by Fleet setup with KMS in [autosharding configuration](https://github.com/kubernetes/kube-state-metrics#automated-sharding)
[Elastic Agent standalone - With KSM in autosharding configuration](./ksm-autosharding/elastic-agent-standalone/) | Standalone Elastic Agent setup with KSM in [autosharding configuration](https://github.com/kubernetes/kube-state-metrics#automated-sharding)

How to choose the appropriate scenario:

- `Default` Elastic agent scenario, deploy Elastic Agent as Daemonset. The default installation method, that will deploy one agent per Kubernetes node.
- `KSM in autosharding configuration` scenario, installs Elastic Agents (that only collect Kube-state-Metrics metrics), along with the KSM as a Side Container. An additional Elastic Agent Leader will be installed as `Daemonset` and will be responsible for the rest of metrics collection. *This scenario is suitable in large Kubernetes deployments*. For more information see [section below](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/README.md#kube-state-metrics-ksm-in-autosharding-configuration)

### How to use the kustomize templates

Navigate to the scenario you want to install:

E.g. we want to install the default Elastic Agent Scenario with kustomize.

```bash
cd elastic-agent-kustomize/default/elastic-agent-standalone
kubectl apply -k .
```

> Since Kubernetes version 1.14, Kubectl supports the usage of kustomize

### Kube State Metrics (KSM) in autosharding configuration

The suggested method of installing Elastic Agent in large Kubernetes clusters is to install Elastic Agent as a Side Container with KSM in order to collect the KSM metrics. As Kubernetes cluster becomes larger, we increase the number of KSM shards. That said, we have a dedicated Elastic Agent to collect from specific KSM shard endpoint. Those are installed as part of [Statefulset](./elastic-agent-kustomize/ksm-autosharding/elastic-agent-standalone/base/elastic-agent-standalone-ksm-statefulset-configmap.yaml).

Apart from the KSM metrics, the rest of the metrics are collected from Elastic Agents deployed as [daemonsets](./elastic-agent-kustomize/ksm-autosharding/elastic-agent-standalone/base/elastic-agent-standalone-ksm-daemonset-configmap.yaml)

More information about running Elastic Agent along with KSM in sharding mode see in [elastic-agent-ksm-sharding](https://github.com/elastic/elastic-agent/blob/main/docs/elastic-agent-ksm-sharding.md)
