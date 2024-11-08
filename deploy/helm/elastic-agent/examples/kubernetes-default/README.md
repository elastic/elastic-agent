# Example: Kubernetes Integration with default chart values

In this example we install the built-in `kubernetes` integration with the default built-in values.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

## Run:

#### Public image registry:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
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

1. The Kibana `kubernetes`-related dashboards should start showing up the respective info.
