# Example: Managed by Fleet Elastic Agent (credentials from Kubernetes Secret)

In this example we deploy an Elastic Agent that is managed by [Fleet](https://www.elastic.co/guide/en/fleet/current/manage-agents-in-fleet.html), reading the Fleet URL and enrollment token from an existing Kubernetes Secret. This is useful when using secret management tools like [external-secrets](https://external-secrets.io/) to distribute credentials across clusters without embedding them in Helm values.

## Prerequisites:

1. Follow [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up an agent policy and enroll an agent to it. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).

2. Create a Kubernetes Secret containing the Fleet URL and enrollment token:
    ```console
    kubectl create secret generic fleet-credentials \
      --from-literal=url=$FLEET_URL \
      --from-literal=token=$FLEET_TOKEN \
      -n <your-namespace>
    ```

3. Build the dependencies of the Helm chart:
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```

## Run:

```console
helm install elastic-agent ../../ \
     --set agent.fleet.enabled=true \
     --set agent.fleet.urlFromSecret.name=fleet-credentials \
     --set agent.fleet.urlFromSecret.key=url \
     --set agent.fleet.tokenFromSecret.name=fleet-credentials \
     --set agent.fleet.tokenFromSecret.key=token \
     --set agent.fleet.preset=perNode \
     -n <your-namespace>
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. Install Kubernetes integration to the agent policy that corresponds to the enrolled agents.
3. The Kibana `kubernetes`-related dashboards should start showing the respective info.
