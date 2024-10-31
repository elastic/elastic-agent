# Example: System Integration with custom auth log paths

In this example we install the built-in `system` integration and specify custom paths for the auth logs stream (see [agent-system-values.yaml](agent-system-values.yaml)).

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `system` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-system-values.yaml \
     --set outputs.default.type=ESSecretAuthAPI \
     --set outputs.default.secretName=es-api-secret
```

## Validate:

1. The Kibana `system`-related dashboards should start showing up the respective info.
