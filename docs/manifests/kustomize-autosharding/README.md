# Agent installed as side container with Kube State Metrics 

Follow below instructions to install Elastic Agent as side-container with Kube State Metrics Pods.

1. Download the Kube-state-metrics manifests

```bash
git clone git@github.com:kubernetes/kube-state-metrics.git
```

1. Navigate to the directory of Autosharding example

```bash
cd kube-state-metrics/examples/autosharding
```

1. Download the [`./elastic-agent-kustomize`](./elastic-agent-kustomize) folder inside the same folder

1. Edit or replace the already existing kustomization.yaml file with the example [kustomization.yaml](./kustomization.yaml)

The new `kustomization.yaml` should include:

```yaml
[outut truncated ...]
resources:
  - cluster-role-binding.yaml
  - cluster-role.yaml
  - role-binding.yaml
  - role.yaml
  - service-account.yaml
  - service.yaml
  - statefulset.yaml
  - ./elastic-agent-kustomize


patches:
- path: elastic-agent-kustomize/agent-statefulset.yaml
  target:
    kind: StatefulSet
```

1. Update number of ReplicaSets and re-apply:

```bash
kubectl apply -k .
```
