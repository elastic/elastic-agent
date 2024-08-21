# Example: Kubernetes Integration only for container logs

In this example we install the built-in `kubernetes` integration and set it to extract only container logs.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes.yaml \
     --set outputs.default.type=ESSecretAuthAPI \
     --set outputs.default.secretName=es-api-secret
```

## Validate:

1. Container logs should appear in Kibana at Observability=>Logs=>Stream.
