# Example: Managed by Fleet Elastic Agent

In this example we deploy an Elastic Agent that is managed by [Fleet](https://www.elastic.co/guide/en/fleet/current/manage-agents-in-fleet.html).

## Prerequisites:
1. Follow [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up an agent policy and enroll an agent to it. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).

2. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```

## Run:

```console
helm install elastic-agent ../../ \
     --set agent.fleet.enabled=true \
     --set agent.fleet.url=$FLEET_URL \
     --set agent.fleet.token=$FLEET_TOKEN \
     --set agent.fleet.preset=perNode
     -n kube-system
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. Install Kubernetes integration to the agent policy that corresponds to the enrolled agents.
3. The Kibana `kubernetes`-related dashboards should start showing the respective info.

## Note:

1. In this example we deploy an Elastic Agent that is managed by Fleet using the built-in `perNode` preset (`DaemonSet`) targeting kubernetes monitoring. However, a user-defined agent `preset`, for different use cases, can be used as well, e.g. by using the following configuration:
    ```yaml
    agent:
      fleet:
        enabled: true
        url: $FLEET_URL # replace with Fleet URL
        token: $FLEET_TOKEN # replace with Fleet Enrollment token
        preset: changeme # replace with the custom used-defined preset name
    ```

2. If you want to disable kube-state-metrics installation with the elastic-agent Helm chart, you can set `kube-state-metrics.enabled=false` in the Helm chart.
