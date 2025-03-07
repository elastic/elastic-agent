# Example: Kubernetes Integration with default chart values

In this example we install the built-in `kubernetes` integration with the default built-in values and we adjust the priority class of the two built-in presets, namely `perNode` and `clusterWide`.

## Chart Values

Below we showcase how to adjust the priority class of the two built-in presets, namely `perNode` and `clusterWide`.

```yaml
# part of values.yaml
agent:
  presets:
    perNode:
      priorityClass:
        create: true # instruct helm to create this priority class
        value: 456
        globalDefault: true
        preemptionPolicy: "Never"
        description: "Elastic Agent per-node preset priority class"
    clusterWide:
      priorityClass:
        create: false # instruct helm to use a pre-existing priority class
        name: "agent-clusterwide-pc"
```

## Prerequisites:
1. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
2. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

3. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

## Run:

#### Public image registry:
```console
helm install elastic-agent ../../ \
     -f ./values.yaml \
     --set outputs.default.type=ESSecretAuthAPI \
     --set outputs.default.secretName=es-api-secret
```


#### Private image registry:
Create secret with the contents of docker auth config
```
kubectl create secret generic regcred --from-file=.dockerconfigjson=<your home folder here>/.docker/config.json --type=kubernetes.io/dockerconfigjson
```

Install elastic-agent
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
     --set 'agent.imagePullSecrets[0].name=regcred' \
     --set outputs.default.type=ESSecretAuthAPI \
     --set outputs.default.secretName=es-api-secret
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. The Kibana `kubernetes`-related dashboards should start showing up the respective info.

## Note:

1. If you want to disable kube-state-metrics installation with the elastic-agent Helm chart, you can set `kube-state-metrics.enabled=false` in the Helm chart. The helm chart will use the value of `kubernetes.state.host` to configure the elastic-agent input.
