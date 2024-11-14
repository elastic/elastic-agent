# Example: Kubernetes Integration with User-created cluster role

In this example we define a `nginx` custom integration alongside a custom agent preset defined in [agent-nginx-values.yaml](agent-nginx-values.yaml) including the use of a user-created cluster role. Note that the user is responsible for assigning the correct permissions to the cluster role.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `nginx` integration assets are installed through Kibana

3. Create a cluster role.

    ```console
    kubectl create clusterrole user-cr --verb=get,list,watch --resource=pods,namespaces,nodes,replicasets,jobs
    ```

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
