# Example: Kubernetes Integration with hint-based autodiscover

In this example we install the built-in `kubernetes` integration and enable the feature of hint-based autodiscover. With this feature, the kubernetes integration can monitor the creation of pods that bear specific annotations based on which the agent loads dynamically the respective integration. In the context of this example, we showcase hint-based autodiscover with `redis` integration.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `redis` integration assets are installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

3. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
## Run:
1. Install Helm chart
    ```console
    helm install elastic-agent ../../ \
        -f ./agent-kubernetes-values.yaml \
        --set outputs.default.type=ESSecretAuthAPI \
        --set outputs.default.secretName=es-api-secret
    ```

2. Install a redis pod with the appropriate annotations
    ```console
   kubectl apply -f ./redis.yaml
    ```

## Validate:

1. The Kibana `redis`-related dashboards should start showing up the respective info.
