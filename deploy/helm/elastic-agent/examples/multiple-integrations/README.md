# Example: Multiple Integrations

In this example we install the built-in `kubernetes` integration and a `nginx` custom integration based on the same cluster-wide agent preset that the `kubernetes` integration utilises. Also, we enable the hints-based autodiscovery supported in the `kubernetes` integration.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `kubernetes`, `redis`, and `nginx` integration assets are installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

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
        -f ./agent-nginx-values.yaml \
        --set outputs.default.type=ESSecretAuthAPI \
        --set outputs.default.secretName=es-api-secret
    ```

2. Install a redis pod with the appropriate annotations
    ```console
   kubectl apply -f ./redis.yaml
    ```
3. Install the nginx deployment
    ```console
   kubectl apply -f ./nginx.yaml
    ```

## Validate:

1. The Kibana dashboards for the `kubernetes`, `redis` and `nginx` integration should start showing data.
