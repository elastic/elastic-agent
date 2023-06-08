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

