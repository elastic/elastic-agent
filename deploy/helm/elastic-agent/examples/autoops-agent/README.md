# Example: Managed by Opex  Agent

In this example we deploy an Elastic AutoOps Agent that is managed by Opex team .


## Run:

There are 2 kinds of installations, related to auth method

### for API_KEY installation

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

### for Username:password (Basic auth) installation

```console
helm install ./deploy/helm/elastic-agent -n kube-system \
  --set kube-state-metrics.enabled=false \
  --set kubernetes.enabled=false \
  --set autoOps.enabled=true \
  --set-string autoOps.autoops_token="tok-123" \
  --set-string autoOps.autoops_otel_url="https://otel.example.com:4318" \
  --set-string autoOps.autoops_temp_resource_id="res-abc" \
  --set-string autoOps.es_username="elastic" \
  --set-string autoOps.es_username="es_pass"
```
