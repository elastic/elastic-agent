# Example: Managed by Fleet Elastic Agent with self-signed certificates

This example demonstrates deploying an Elastic Agent that is managed by Fleet with custom fleet-related certificates, including CA certificates and client certificates for mutual TLS (mTLS).

## Prerequisites:
## Prerequisites

Before deploying, you should:

1. Set up an [Agent policy](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) in Fleet.
2. Follow [this guide](https://www.elastic.co/guide/en/fleet/8.17/add-fleet-server-kubernetes.html#add-fleet-server-kubernetes-cert-prereq) to set up an agent policy and enroll an agent to it. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).
3. Create Kubernetes secrets holding the necessary certificates (CA certificate, client certificate, and client private key) or have the certificate files available locally to use with the `--set-file` Helm CLI argument.
4. Build the dependencies of the Helm chart
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
     --set agent.fleet.preset=perNode \
     --set-file agent.fleet.ca.value=path/to/ca.crt \
     --set-file agent.fleet.agentCert.value=path/to/agent.crt \
     --set-file agent.fleet.agentCertKey.value=agent.key \
     --set-file agent.fleet.kibanaCA.value=path/to/kibanaca.crt \
     -n kube-system
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. Install Kubernetes integration to the agent policy that corresponds to the enrolled agents.
3. The Kibana `kubernetes`-related dashboards should start showing the respective info.

