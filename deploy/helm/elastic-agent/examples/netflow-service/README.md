# Example: Netflow Custom Integration

In this example we define a `netflow` custom integration alongside a custom agent preset defined in [agent-netflow-values.yaml](agent-netflow-values.yaml). Also, we disable all `kubernetes` related providers and creation of cluster role and service account, as they are not required for this example.

## Prerequisites:
1. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

2. `NetFlow Records` integration assets are installed through Kibana

## Run:
1. Install Helm chart
    ```console
    helm install elastic-agent ../../ -f ./agent-netflow-values.yaml
    ```

2. Run the netflow data generator deployment
    ```console
   kubectl run -it --rm netflow-generator --image=networkstatic/nflow-generator --restart=Never -- -t agent-netflow-elastic-agent.default.svc.cluster.local -p 2055
    ```

## Validate:

1. The Kibana `netflow`-related dashboards should start showing netflow related data.
