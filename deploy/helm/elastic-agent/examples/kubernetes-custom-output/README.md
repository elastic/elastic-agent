# Example: Kubernetes Integration with default chart values

In this example we install the built-in `kubernetes` integration with the default built-in values and a different agent output with ssl settings that allow to connect to an Elasticsearch cluster that is exposed with a self-signed certificate, namely `test`.

## Prerequisites:
1. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
2. A k8s secret that contains the connection details to an Elasticsearch cluster, such as the URL and the API key ([Kibana - Creating API Keys](https://www.elastic.co/guide/en/kibana/current/api-keys.html)):
    ```console
    kubectl create secret generic es-api-secret \
       --from-literal=api_key=... \
       --from-literal=url=...
    ```

3. `kubernetes` integration assets installed through Kibana ([Kibana - Install and uninstall Elastic Agent integration assets](https://www.elastic.co/guide/en/fleet/current/install-uninstall-integration-assets.html))
4. The CA certificate, that validates the self-signed server certificate, stored in the file `ca.crt`. Example content of the `ca.crt` file.
     ```
     -----BEGIN CERTIFICATE-----
     MIIDSjCCAjKgAwIBAgIRALfMeXFmYLUW4HaNXLzfP4cwDQYJKoZIhvcNAQELBQAw
     LzETMBEGA1UECxMKbW9uaXRvcmluZzEYMBYGA1UEAxMPbW9uaXRvcmluZy1odHRw
     MB4XDTI0MTIxMTEwMTMzNVoXDTI1MTIxMTEwMjMzNVowLzETMBEGA1UECxMKbW9u
     aXRvcmluZzEYMBYGA1UEAxMPbW9uaXRvcmluZy1odHRwMIIBIjANBgkqhkiG9w0B
     AQEFAAOCAQ8AMIIBCgKCAQEAsljXOJrCsvZGHr2SroKUGJOnJwtz8VTx2spQ96OO
     8Q+Tw8gX5C32bjplwAeQsnZ7i5YRRLneaG6NXJuaUEDefsKeG6jdN/bjce+Sz5xm
     U6guXe3TuIyk0+UoFtOzZ1lYUNk6lg9+60iOllRO3xI7SwxqKAaC4KKs7QL1jQCR
     Q14QedcPrS4v76OT+TJvYWrbTFLtYYvfJDGop5EE90v7iB5j0ehSLjfC2R4CD5Kr
     OSYJrGqnhnznbUUjulVqCkPKmgZdcvcIBn4NnZlN6oYzwhRHSSj6r3sy11j3A6SA
     7KeG+IlY+LmRtrj85tiRJ3pXz1FD2d/Mf6cNI6lBGRrNZwIDAQABo2EwXzAOBgNV
     HQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8GA1Ud
     EwEB/wQFMAMBAf8wHQYDVR0OBBYEFMgVU7RwXciOOz18FcQDTQZXy9gIMA0GCSqG
     SIb3DQEBCwUAA4IBAQCgOSe2s3Xc0QKR+86xmoAADpoe7SFT0Yyh3rMjL+0p02m3
     CqrILqCRNFu9az8gc47hUt9Crb1BXmTR0Sb23M1NvGmR2D2K7CLp/SvkAP6RlB4M
     dZ70UKw4ohq+VSSSiLOoHYdlH46xtunLL31GLYRwD+OgeKAc5pwqWgZkndzxrouB
     uNyoxB5NGvaVUqIouILQ9V2fvraCNf+RxuQ0AaPxdt/CNpFaXpbJBuXJCphlydu0
     KztVqRv5EZjuYpcXDfGP9BEvMy6o895H4iG0M2wb2e3WEDo6jH5pecZfc4yz8iae
     jLwbOPbWqOGRkxTMLOV6Q1dtr09zf2SuOQuxm7F2
     -----END CERTIFICATE-----
     ```

## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
     --set outputs.test.type=ESSecretAuthAPI \
     --set outputs.test.secretName=es-api-secret \
     --set-file 'outputs.test.certificate_authorities[0].value=ca.crt' \
     --set agent.presets.perNode.agent.monitoring.use_output=test \
     --set agent.presets.clusterWide.agent.monitoring.use_output=test \
     --set kubernetes.output=test
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. The Kibana `kubernetes`-related dashboards should start showing up the respective info.
3. Kubernetes data ship to the Elasticsearch cluster of the `test` output.

## Note:

1. If you want to disable kube-state-metrics installation with the elastic-agent Helm chart, you can set `kube-state-metrics.enabled=false` in the Helm chart. The helm chart will use the value of `kubernetes.state.host` to configure the elastic-agent input.
