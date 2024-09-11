# Example: Nginx Custom Integration

In this example we define a `nginx` custom integration alongside a custom agent preset defined in [agent-nginx-values.yaml](agent-nginx-values.yaml).

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `nginx` integration assets are installed through Kibana

## Run:
1. Install Helm chart
    ```console
    helm install elastic-agent ../../ \
         -f ./agent-nginx-values.yaml \
         --set outputs.default.type=ESSecretAuthAPI \
         --set outputs.default.secretName=es-api-secret
    ```

2. Install the nginx deployment
    ```console
   kubectl apply -f ./nginx.yaml
    ```

## Validate:

1. The Kibana `nginx`-related dashboards should start showing nginx related data.
