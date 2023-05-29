# Agent installed as side container with Kube State Metrics 

Follow below instructions to install Elastic Agent as side-container with Kube State Metrics Pods.

1. Download the Kube-state-metrics manifests

```bash
git clone git@github.com:kubernetes/kube-state-metrics.git
```

1. Naviagte to the directory of Autosharding example

```bash
cd kube-state-metrics/examples/autosharding
```

1. Copy the [`./elastic-agent`](./elastic-agent) folder inside the same folder 

1. Edit or replace the already existing kustomization.yaml file with the example [kustomization.yaml](./kustomization.yaml)

The new `kustomization.yaml` should inlcude:

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
  - ./elastic-agent


patches:
- path: elastic-agent/agent-statefulset.yaml
  target:
    kind: StatefulSet
```

1. Update number of Replicasets  and rerun:

```bash
kubectl apply -k .
```
