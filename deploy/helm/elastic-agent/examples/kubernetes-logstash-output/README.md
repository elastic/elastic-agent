# Example Kubernetes Integration with Logstash output

In this example we install the built-in `kubernetes` integration with the default built-in values and a different agent output with ssl settings that allow to connect to a Logstash cluster that is exposed with mtls using a self-signed certificate.

## Prerequisites:
1. Build the dependencies of the Helm chart
    ```console
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm dependency build ../../
    ```
2. A k8s secret that contains the client cert and key for [mtls to a logstash cluster](https://www.elastic.co/docs/reference/fleet/secure-logstash-connections) stored in the files tls.crt and tls.key.
    ```console
    kubectl create secret tls cert-secret \
       --cert=tls.crt \
       --key=tls.key
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
5. A logstash instance running with the server tls certificates that match the client set used by elastic agent. Running a pipeline similar to the below:

```
    input {
      elastic_agent {
        port => 5044
        ssl_enabled => true
        ssl_certificate_authorities => ["/opt/logstash/ssl/ca.crt"]
        ssl_certificate => "/opt/logstash/ssl/logstash.crt"
        ssl_key => "/opt/logstash/ssl/logstash.pkcs8.key"
        ssl_client_authentication => "required"
      }
    }
    filter {
       elastic_integration {
         cloud_id => "${CLOUD_ID}"
         username => "${ES_USER}"
         password => "${ES_PASSWORD}"
       }
    }
    output {
        elasticsearch {
            cloud_id => "${CLOUD_ID}"
            user => "${ES_USER}"
            password => "${ES_PASSWORD}"
            data_stream => "true"
            manage_template => "false"
        }
    }
```
## Run:
```console
helm install elastic-agent ../../ \
     -f ./agent-kubernetes-values.yaml \
     --set outputs.test.hosts[0]="logstash-agent.default.svc.cluster.local:5044" \
     --set outputs.test.type=Logstash \
     --set-file outputs.test.ssl.certificateAuthorities[0].value=ca.crt \
     --set outputs.test.ssl.certificate.valueFromSecret.key=tls.crt \
     --set outputs.test.ssl.certificate.valueFromSecret.name=cert-secret \
     --set outputs.test.ssl.key.valueFromSecret.key=tls.key \
     --set outputs.test.ssl.key.valueFromSecret.name=cert-secret \
     --set agent.presets.perNode.agent.monitoring.use_output=test \
     --set agent.presets.clusterWide.agent.monitoring.use_output=test \
     --set kubernetes.output=test
```

## Validate:

1. `kube-state metrics` is installed with this command `kubectl get deployments -n kube-system kube-state-metrics`.
2. Kubernetes data ship to the Logstash Cluster of the `test` output.
3. The Kibana `kubernetes`-related dashboards should start showing up the respective info.

## Note:

1. If you want to disable kube-state-metrics installation with the elastic-agent Helm chart, you can set `kube-state-metrics.enabled=false` in the Helm chart. The helm chart will use the value of `kubernetes.state.host` to configure the elastic-agent input.
