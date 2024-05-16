# Kustomize Templates

The list below includes the official [kustomize](https://github.com/kubernetes-sigs/kustomize) templates to run them in Kubernetes:

Agent Scenario | Description
---- | ----
[Elastic Agent managed - Default ](./elastic-agent-kustomize/default/elastic-agent-managed/) | Default Elastic Agent managed by Fleet setup. Kube-state-metrics (KSM) is installed automatically.
[Elastic Agent standalone Default ](./elastic-agent-kustomize/default/elastic-agent-standalone/) | Default Standalone Elastic Agent setup. Kube-state-metrics (KSM) is installed automatically.

## Using above templates

Users can clone this repository to use the provided kustomize templates.

For *Managed Elastic Agent*, please update the following secrets inside main kustomization.yaml:

- ${fleet_url}: Fleet Server URL to enroll the Elastic Agent into. FLEET_URL can be found in Kibana, go to Management > Fleet > Settings
- ${enrollment_token}: Elasticsearch API key used to enroll Elastic Agents in Fleet (https://www.elastic.co/guide/en/fleet/current/fleet-enrollment-tokens.html#fleet-enrollment-tokens)

```yaml
secretGenerator:
    - name: elastic-agent-creds
      literals:
        - host=${fleet_url}
        - api_key=${enrollment_token}
```

For *Standalone Elastic Agent*, please update the following secrets inside main kustomization.yaml:

- ${es_host}: The Elasticsearch host to communicate with
- ${api_key}: The API Key with access privilleges to connect to Elasticsearch. https://www.elastic.co/guide/en/fleet/current/grant-access-to-elasticsearch.html#create-api-key-standalone-agent


## Remote usage of kustomize templates

Users can use following commands:

Managed Elastic Agent:

```bash
kubectl kustomize https://github.com/elastic/elastic-agent/deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-managed\?ref\=main | 
sed -e 's/JHtlbnJvbGxtZW50X3Rva2VufQo=/<base64_fleet_enrollment_token>/g' -e 's/JHtmbGVldF91cmx9Cg==/<base64_fleet_url>/g'  | 
kubectl apply -f-
```

Standalone Elastic Agent:

```bash
kubectl kustomize https://github.com/elastic/elastic-agent/deploy/kubernetes/elastic-agent-kustomize/default/elastic-agent-standalone\?ref\=main | 
sed -e 's/JHthcGlfa2V5fQo=/<base64_api_key>/g' -e 's/JHtlc19ob3N0fQo=/<base64_es_host>/g'  | 
kubectl apply -f-
```

> NOTE: Base64 values
    ```bash
    ❯ echo '${api_key}' | base64
    JHthcGlfa2V5fQo=
    ❯ echo '${fleet_url}' | base64
    JHtmbGVldF91cmx9Cg==
    >echo '${enrollment_token}' | base64
    JHtlbnJvbGxtZW50X3Rva2VufQo=
    ❯ echo '${es_host}' | base64
    JHtlc19ob3N0fQo=
    ❯ echo JHtlc19ob3N0fQo= | base64 -D
    ${es_host}
    ```

## Updating kustomize templates

The included kustomize templates are being produced based on [Makefile](deploy/kubernetes/Makefile) by relevant automation: `GENERATEKUSTOMIZE=true make ci-create-kustomize`

The current templates are using patches as defined [here](./elastic-agent-kustomize/default/elastic-agent-managed/kustomization.yaml)
