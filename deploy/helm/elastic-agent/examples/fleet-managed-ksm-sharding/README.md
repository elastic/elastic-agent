# Example: Managed by Fleet Elastic Agent

In this example we will perform two Helm chart installations, one installing elastic-agent as a Daemonset and the other installing kube-state-metrics with the `autosharding` feature enabled and elastic-agent as a sidecar container. All the agents are managed by [Fleet](https://www.elastic.co/guide/en/fleet/current/manage-agents-in-fleet.html). Such a type of setup is recommended for big k8s clusters, featuring a lot of k8s object, where scaling of kube-state-metrics extraction is required.

## Run:

1. Follow [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up an agent policy and enroll an agent to it. In the policy unselect the "Collect system logs and metrics" options and continue to agent enrollment. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).
2. Install `kube-state-metrics` with the `autosharding` feature enabled and an elastic-agent as a sidecar container.
   ```console
    helm install elastic-agent-ksm ../../ \
      --set agent.fleet.enabled=true \
      --set agent.fleet.url=$FLEET_URL \
      --set agent.fleet.token=$FLEET_TOKEN \
      --set agent.fleet.preset='' \
      --set kubernetes.state.agentAsSidecar.enabled=true \
      -n kube-system
    ```
3. In the associated policy from the previous steps install the Kubernetes integration and **enable only** the "Collect Kubernetes metrics from kube-state-metrics".
4. Follow again [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up a different agent policy and enroll an agent to it. Extract again the Fleet URL (`--url=$NEW_FLEET_URL`) and Enrollment token (`--enrollment-token=$NEW_FLEET_TOKEN`).
5. Install elastic-agent as a Daemonset without kube-state-metrics.
    ```console
    helm install elastic-agent ../../ \
      --set agent.fleet.enabled=true \
      --set agent.fleet.url=$NEW_FLEET_URL \
      --set agent.fleet.token=$NEW_FLEET_TOKEN \
      --set agent.fleet.preset='perNode' \
      --set kube-state-metrics.enabled=false \
      -n kube-system
    ```
6. In the latter agent policy install the Kubernetes integration and keep the option "Collect Kubernetes metrics from kube-state-metrics" **disabled**.

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get sts -n kube-system kube-state-metrics`.
2. The Kibana `kubernetes`-related dashboards should start showing the respective info.
