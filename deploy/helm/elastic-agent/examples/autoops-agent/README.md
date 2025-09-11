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
helm install ./deploy/helm/elastic-agent -n kube-system \
  --set kube-state-metrics.enabled=false \
  --set kubernetes.enabled=false \
  --set autoOps.enabled=true \
  --set-string autoOps.autoops_token="tok-123" \
  --set-string autoOps.autoops_otel_url="https://otel.example.com:4318" \
  --set-string autoOps.autoops_temp_resource_id="res-abc" \
  --set-string autoOps.es_api_key="API_KEY_123"

```

## Note:

1. In this example we deploy an AutoOps agent that sends data to an Otel collector, by using the following configuration:
    ```yaml
    autoOps:
    enabled: true
    autoops_token: "REPLACE_ME_TOKEN" #Replace with your AutoOps Token (Provided by AutoOps installation wizard)
    autoops_otel_url: "https://otel.example.com:4318" #Repalce with Otel collector URL (Provided by AutoOps installation wizard)
    autoops_temp_resource_id: "RESOURCE_ID" # (Provided by AutoOps installation wizard)
    es_api_key: "REPLACE_ME_API_KEY" #Replace with your ElasticSearch cluster's API_KEY
    es_username: ""
    es_password: ""
    ```
