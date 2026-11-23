# Example: Kubernetes Integration on OpenShift (unprivileged)

In this example we install the built-in `kubernetes` integration on OpenShift with an unprivileged agent.

## Prerequisites:
1. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
2. A k8s secret that contains the connection details to an Elasticsearch cluster such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

3. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))

4. Permissions to create SCCs and ClusterRoles, and RoleBindings in the release namespace.

## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
     --set outputs.default.type=ESSecretAuthAPI \
     --set outputs.default.secretName=es-api-secret
```

## Validate:

1. The agent pods are ready, as shown by this command `kubectl get daemonsets,deployments -l app.kubernetes.io/name=elastic-agent`.
2. `kube-state metrics` is installed with this command `kubectl get deployments kube-state-metrics`.
3. The Kibana `kubernetes`-related dashboards should start showing up the respective info.

## Note:

1. This example sets `agent.openshift.enabled=true` so that `helm template` renders the OpenShift objects without access to a cluster. The default value `auto` detects OpenShift from the API groups of the cluster.
2. If you want to manage the SCC and its bindings yourself, you can set `agent.openshift.securityContextConstraints.create=false` in the Helm chart.
