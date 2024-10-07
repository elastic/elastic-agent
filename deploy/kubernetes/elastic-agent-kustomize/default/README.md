# Kustomize Templates

The list below includes the official [kustomize](https://github.com/kubernetes-sigs/kustomize) templates to run them in Kubernetes:

Agent Scenario | Description
---- | ----
[Elastic Agent managed - Default ](./elastic-agent-managed/) | Default Elastic Agent managed by Fleet setup. Kube-state-metrics (KSM) is installed automatically.
[Elastic Agent standalone Default ](./elastic-agent-standalone/) | Default Standalone Elastic Agent setup. Kube-state-metrics (KSM) is installed automatically.

## Using above templates

Users can clone this repository to use the provided kustomize templates.

For *Managed Elastic Agent*, please update the following variables inside main kustomization.yaml:

- %FLEET_URL%: Fleet Server URL to enroll the Elastic Agent into. FLEET_URL can be found in Kibana, go to Management > Fleet > Settings
- %ENROLLMENT_TOKEN%: Elasticsearch API key used to [enroll Elastic Agents](https://www.elastic.co/guide/en/fleet/current/fleet-enrollment-tokens.html#fleet-enrollment-tokens) in Fleet. *This should be encoded as base64 value because it will be stored as Kubernetes secret*

Eg.

```yaml
secretGenerator:
  - name: elastic-agent-creds
    literals:
      - enrollment_token=%ENROLLMENT_TOKEN%
```

For *Standalone Elastic Agent*, please update the following secrets inside main [kustomization.yaml](./elastic-agent-managed/kustomization.yaml):

- %ES_HOST%: The Elasticsearch host to communicate with
- %API_KEY: The API Key with access privileges to connect to Elasticsearch. See [create-api-key-standalone-agent](https://www.elastic.co/guide/en/fleet/current/grant-access-to-elasticsearch.html#create-api-key-standalone-agent). *This should be encoded as base64 value because it will be stored as Kubernetes secret*
- %CA_TRUSTED%: The ssl.ca_trusted_fingerprint in order the elastic agent to be able to trust the certificate authority of the Elasticsearch output.
- %ONBOARDING_ID%: A string that will be added as a new field and will denote a specific installation. *By default, this will be added to state_pod dataset.*

## Remote usage of kustomize templates

Users can use following commands:

Managed Elastic Agent:

```bash
❯ kubectl https://github.com/elastic/elastic-agent/deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-maanged\?ref\=main | sed -e "s/JUVOUk9MTE1FTlRfVE9LRU4l/base64_ENCODED_ENROLLMENT_TOKEN/g" -e "s/%FLEET_URL%/https:\/\/localhost:9200/g" | kubectl apply -f-

```

Standalone Elastic Agent:

```bash
kubectl kustomize https://github.com/elastic/elastic-agent/deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone\?ref\=main | sed -e "s/JUFQSV9LRVkl/<base64_encoded_APIKEY>/g" -e "s/%ES_HOST%/https:\/\/localhost:9200/g" -e "s/%CA_TRUSTED%/ca_trusted_fingerprint/g" -e "s/%ONBOARDING_ID%/12345/g" | kubectl apply -f-
```

Examples of Base64 encoded values:

```bash
❯ echo -n %API_KEY% | base64
JUFQSV9LRVkl

echo -n %ENROLLMENT_TOKEN% | base64
JUVOUk9MTE1FTlRfVE9LRU4l

❯ echo -n JUVOUk9MTE1FTlRfVE9LRU4l | base64 -D
%ENROLLMENT_TOKEN%%
```

NOTE: `echo -n` flag needs to be provided in order to have correct base64 encoding. The echo command adds an extra line by default which needs to be avoided.

## Updating kustomize templates

The included kustomize templates are being produced based on [Makefile](../../Makefile) by running: `GENERATEKUSTOMIZE=true make ci-create-kustomize`

The current templates are using patches as defined [here](https://github.com/elastic/elastic-agent/blob/main/deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed/kustomization.yaml)
