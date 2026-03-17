# Example: Cloud Defend (Defend for Containers) in Standalone Mode

This example deploys the [cloud-defend](https://www.elastic.co/docs/current/integrations/cloud_defend) integration (Defend for Containers) in **standalone mode** in `kube-system` kubernetes namespace.

## Prerequisites

1. Build the dependencies of the Helm chart
   ```console
   helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
   helm dependency build ../../
   ```

2. Elasticsearch connection. Current version of `cloud-defend` supports only Elasticsearch outpup with `ESPlainAuthAPI` or `ESPlainAuthBasic` output type.

3. Node requirements. Cloud Defend requires a node with bpf/lsm enabled, and it should allow mounting of `/sys/kernel/debug`, `/boot`, `/sys/fs/bpf`, and `/sys/kernel/security` directories.

## Run

```console
helm install elastic-agent ../../ \
   -f ./cloud-defend-values.yaml \
   --set outputs.default.type=ESPlainAuthAPI \
   --set outputs.default.url=<ELASTICSEARCH_URL> \
   --set outputs.default.api_key=<ELASTICSEARCH_API_KEY> \
```

## Validate

1. Verify the DaemonSet is running:
   ```console
   kubectl get daemonset -l app.kubernetes.io/name=elastic-agent
   ```

2. Check that agent pods are running on each node:
   ```console
   kubectl get pods -l app.kubernetes.io/name=elastic-agent -o wide
   ```
