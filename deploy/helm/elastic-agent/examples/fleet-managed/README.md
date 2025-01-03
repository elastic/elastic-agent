# Example: Managed by Fleet Elastic Agent

In this example we deploy an Elastic Agent that is managed by [Fleet](https://www.elastic.co/guide/en/fleet/current/manage-agents-in-fleet.html).

## Prerequisites:
1. Follow [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up an agent policy and enroll an agent to it. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).

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

1. [Optional] Install kube-state metrics if you want to see the KSM related metrics `kubectl apply -k https://github.com/kubernetes/kube-state-metrics`.
2. Install Kubernetes integration to the agent policy that you created in Fleet. If you didn't install kube-state metrics from above, make sure to disable them in the integration.
3. The Kibana `kubernetes`-related dashboards should start showing the respective info.

## Note:

In this example we deploy an Elastic Agent that is managed by Fleet using the built-in `perNode` preset (`DaemonSet`) targeting kubernetes monitoring. However, a user-defined agent `preset`, for different use cases, can be used as well, e.g. by using the following configuration:
```yaml
agent:
  fleet:
    enabled: true
    url: $FLEET_URL # replace with Fleet URL
    token: $FLEET_TOKEN # replace with Fleet Enrollment token
    preset: perNode
```
