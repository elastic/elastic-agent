# Run/Test Elastic Agent on a local Kubernetes cluster

## Prerequisites

- Install [kubectl](https://kubernetes.io/docs/tasks/tools/#kubectl)
- Install a local k8s distribution and create a cluster:
  - [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
  - [k3d](https://k3d.io/v5.5.1/#installation)
  - [minikube](https://minikube.sigs.k8s.io/docs/start/) (not tested)
- Clone this repository

## Quickstart

### Standalone or managed mode

There are 2 supported kustomize scenarios:

- `elastic-agent-standalone`
- `elastic-agent-managed`

For brevity, examples below use standalone mode.

### Prepare Kubernetes manifests

Choose one of the following directories:

- Standalone: `deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone`
- Managed: `deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed`

Update placeholders in `kustomization.yaml` for your Elastic Stack environment.

#### Standalone mode placeholders

```yaml
# deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone/kustomization.yaml
secretGenerator:
  - name: elastic-agent-creds
    literals:
      - api_key=%API_KEY%

configMapGenerator:
  - name: elastic-agent-configs
    literals:
      - host=%ES_HOST%
      - ca_trusted=%CA_TRUSTED%
```

#### Managed mode placeholders

```yaml
# deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/kustomization.yaml
secretGenerator:
  - name: elastic-agent-creds
    literals:
      - enrollment_token=%ENROLLMENT_TOKEN%

configMapGenerator:
  - name: elastic-agent-configs
    literals:
      - host=%FLEET_URL%
```

### Deploy Elastic Agent

```shell
kubectl apply -k deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone
```

Check resources:

```shell
kubectl -n kube-system get daemonset,pods | grep elastic-agent
```

Stream logs:

```shell
kubectl -n kube-system logs -l app.kubernetes.io/name=elastic-agent-standalone -c elastic-agent-standalone -f --tail=100
```

### Cleanup

```shell
kubectl delete -k deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone
```

## Additional references

- `deploy/kubernetes/README.md`
- `deploy/kubernetes/elastic-agent-kustomize/default/README.md`
