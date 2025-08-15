# Example: Kubernetes Integration with default chart values

In this example we install the built-in `kubernetes` integration with the default built-in values. We also change the `kube-state-metrics` to run with the `autosharding` feature enabled and include elastic-agent as a sidecar container. Such a type of setup is recommended for big k8s clusters, featuring a lot of k8s resources, where scaling of kube-state-metrics extraction is required.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

3. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
## Run:

#### Public image registry:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml
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
     --set 'agent.imagePullSecrets[0].name=regcred'
```

## Validate:

1. `kube-state metrics` is installed by this command `kubectl get sts -n kube-system kube-state-metrics`.
2. The Kibana `kubernetes`-related dashboards should start showing up the respective info.
