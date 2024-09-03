# Example: Kubernetes Integration with default chart values under ECK operator

In this example we install the built-in `kubernetes` integration with the default built-in values and elastic-agent is managed by [ECK](https://github.com/elastic/cloud-on-k8s) operator.

## Prerequisites:
1. ECK operator installed in the cluster
    ```console
    helm repo add elastic https://helm.elastic.co
    helm repo update
    helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace
    ```

2. Elasticsearch and Kibana installed in the cluster through ECK operator

    ```console
    kubectl apply -f ./elasticsearch.yaml
    ```

3. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

   1. The username to connect to Kibana is `elastic`
   2. To find the password to connect to Kibana, run `kubectl get secrets/elasticsearch-sample-es-elastic-user -n elastic-system -o json | jq -r '.data.elastic' | base64 -d`
   3. Don't forget to forward the port of Kibana to your local machine by running `kubectl port-forward deployments/kibana-sample-kb -n elastic-system 12000:5601`
   4. Open https://localhost:12000 in your browser
   5. Install kubernetes integration through Kibana

## Run:
```console
helm install elastic-agent ../../ \
    -f ./agent-kubernetes-values.yaml
```

## Validate:

1. The Kibana `kubernetes`-related dashboards should start showing up the respective info.
