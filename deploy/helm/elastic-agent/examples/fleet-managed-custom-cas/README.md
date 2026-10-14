# Example: Fleet-managed Elastic Agent trusting a custom CA in browser monitors

In this example we deploy an Elastic Agent managed by [Fleet](https://www.elastic.co/guide/en/fleet/current/manage-agents-in-fleet.html) as a Synthetics private location, and make the browser (Chromium) used by browser monitors trust a private certificate authority. Without this, browser monitors against endpoints signed by that CA fail with `ERR_CERT_AUTHORITY_INVALID`.

The `elastic-agent-complete` image imports every PEM certificate (`*.crt` and `*.pem`) mounted at `/usr/local/share/ca-certificates` into the browser trust store when the container starts. The `agent.customCAs.secretName` value mounts a Secret there.

## Chart Values

```yaml
# part of values.yaml
agent:
  image:
    repository: docker.elastic.co/elastic-agent/elastic-agent-complete # browser monitors need the complete image
  customCAs:
    secretName: corp-cas # existing Secret with the CA certificates
```

## Prerequisites:

1. Follow [this guide](https://www.elastic.co/guide/en/fleet/current/install-fleet-managed-elastic-agent.html#elastic-agent-installation-steps) to set up an agent policy and enroll an agent to it. Do not download any binary, from the proposed enrollment command just extract the Fleet URL (`--url=$FLEET_URL`) and Enrollment token (`--enrollment-token=$FLEET_TOKEN`).

2. Create a Kubernetes Secret containing the Fleet URL and enrollment token:
    ```console
    kubectl create secret generic fleet-credentials \
      --from-literal=url=$FLEET_URL \
      --from-literal=token=$FLEET_TOKEN \
      -n <your-namespace>
    ```

3. Create a Kubernetes Secret with your CA certificate(s). Every key is mounted as a file and must end in `.crt` or `.pem`. A file can hold a bundle with several certificates:
    ```console
    kubectl create secret generic corp-cas \
      --from-file=corp-root.crt=./corp-root.crt \
      -n <your-namespace>
    ```

4. Build the dependencies of the Helm chart:
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```

## Run:

```console
helm install elastic-agent ../../ \
     -f ./custom-cas-values.yaml \
     -n <your-namespace>
```

## Validate:

1. The agent container logs `Imported <n> custom CA certificate(s) from /usr/local/share/ca-certificates into the browser trust store` on start.
2. A browser monitor against an endpoint signed by your CA succeeds without ignoring TLS errors.

## Note:

The agent imports the certificates when the container starts and then re-checks the directory every 30 seconds (set `ELASTIC_AGENT_CUSTOM_CA_RELOAD_INTERVAL` to another number of seconds, or `0` to turn it off). Certificates added, removed or rotated in the Secret are applied without restarting the pods, once Kubernetes has refreshed the mounted files, which can take a minute or so. Browser runs that start after the import use the new set. Changing the Secret's name changes the pod spec, so Helm rolls the pods.
