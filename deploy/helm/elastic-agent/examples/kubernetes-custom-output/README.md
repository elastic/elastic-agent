# Example: Kubernetes Integration with default chart values

In this example we install the built-in `kubernetes` integration with the default built-in values and a different agent output, named `test`.

## Prerequisites:
1. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
2. A k8s secret that contains the connection details to an Elasticsearch cluster, such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

3. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
     --set outputs.test.type=ESSecretAuthAPI \
     --set outputs.test.secretName=es-api-secret \
     --set agent.presets.perNode.agent.monitoring.use_output=test \
     --set agent.presets.clusterWide.agent.monitoring.use_output=test \
     --set kubernetes.output=test
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. The Kibana `kubernetes`-related dashboards should start showing up the respective info.
3. Kubernetes data ship to the Elasticsearch cluster of the `test` output.

## Note:

1. If you want to disable kube-state-metrics installation with the elastic-agent Helm chart, you can set `kube-state-metrics.enabled=false` in the Helm chart. The helm chart will use the value of `kubernetes.state.host` to configure the elastic-agent input.
