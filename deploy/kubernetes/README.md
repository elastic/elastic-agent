# Beats Kubernetes manifests examples

## Getting started

This is the list of officially supported Elastic Agents, with example manifests to run
them in Kubernetes:

Agent Mode | Description
---- | ----
[Elastic Agent managed](elastic-agent-managed) | Elastic Agent managed by Fleet setup
[Elastic Agent standalone](elastic-agent-standalone) | Standalone Elastic Agent setup

> Note: Kube State Metrics Library is not installed as part of the above manifests and needs to be installed additionally

## Kustomize Templates

Additional to the above manifests, the list below includes the official [kustomize](https://github.com/kubernetes-sigs/kustomize) templates to run them in kubernetes:

Agent Scenario | Description
---- | ----
[Elastic Agent managed - Default ](./default/elastic-agent-managed/) | Default Elastic Agent managed by Fleet setup. Includes the installation of Kube State Metrics (KSM) in default configuration.
[Elastic Agent standalone Default ](./default/elastic-agent-standalone/) | Default Standalone Elastic Agent setup
[Elastic Agent managed - With KSM in autosharding configuration ](./ksm-autosharding/elastic-agent-managed/) | Elastic Agent managed by Fleet setup with [KSM in autosharding configuration](https://github.com/kubernetes/kube-state-metrics#automated-sharding)
[Elastic Agent standalone - With KSM in autosharding configuration](./ksm-autosharding/elastic-agent-standalone/) | Standalone Elastic Agent setup with [KSM in autosharding configuration](https://github.com/kubernetes/kube-state-metrics#automated-sharding)

*(KSM = Kube State Metrics)

### How to use the kustomize templates

Navigate to scenario you need to install: 

E.g. we need to install the default Elastic Agent Scenario with kustomize.

```bash
cd elastic-agent-kustomize/default/elastic-agent-standalone
kubectl apply -k .
```

> Since Kubernetes version 1.14, Kubectl supports the use of kustomize

### Kube State Metrics (KSM) in autosharding configuration

The several challenges phased during scaling of Kubernetes cluster are [explained here](https://github.com/elastic/ingest-docs/blob/main/docs/en/ingest-management/elastic-agent/scaling-on-kubernetes.asciidoc)

The suggested method of installing Elastic Agent in large Kubernetes clusters is to install Elastic Agent as a Side Container with KSM in order to collect the KSM metrics. As Kubernetes cluster becomes larger, we increase the number of KSM shards and we have a dedicated Elastic Agent to collect from specific shard endpoint. Those are installed as part of [Statefulset](./elastic-agent-kustomize/ksm-autosharding/elastic-agent-standalone/base/elastic-agent-standalone-ksm-statefulset-configmap.yaml)

Additional to the Elastic Agents for KSM, the rest of metrics are collected from Elastic Agents deployed as [daemonsets](./elastic-agent-kustomize/ksm-autosharding/elastic-agent-standalone/base/elastic-agent-standalone-ksm-daemonset-configmap.yaml)

More information for the configuration of Elastic Agent can be found [here](https://github.com/elastic/elastic-agent/blob/52b681c8c1a77192b8843e4ab140591871d77d24/docs/elastic-agent-ksm-sharding.md)
