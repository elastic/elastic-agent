---
navigation_title: Proxy settings
description: Configuration of the {{agent}}'s proxy settings.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector: ga
products:
  - id: cloud-serverless
  - id: observability
  - id: edot-collector
---

# Configure proxy settings for {{agent}} components

When running the {{agent}} in environments that require outbound traffic to go through a proxy, you must explicitly configure proxy settings.

You may need to configure a proxy if:

- Your app is deployed behind a corporate proxy or firewall.
- Your telemetry is sent to Elastic APM in Elastic Cloud or another hosted destination.
- Network errors such as `Connection timed out` or `SSL handshake failed` appear in logs.

## Available proxy variables

| Variable     | Description                                 |
|--------------|---------------------------------------------|
| HTTP_PROXY   | URL of the proxy server for HTTP requests   |
| HTTPS_PROXY  | URL of the proxy server for HTTPS requests  |
| NO_PROXY     | Comma-separated list of hosts to exclude    |

## Configure proxy settings for the {{agent}}

Most {{agent}} components honor common proxy environment variables. The following examples show how to configure them:

::::{tab-set}

:::{tab-item} Docker run
```bash
docker run -e HTTP_PROXY=http://<proxy.address>:<port> \
           -e HTTPS_PROXY=http://<proxy.address>:<port> \
	        otel/opentelemetry-collector:latest
```
:::

:::{tab-item} Docker compose
```yaml
services:
   edotcollector:
      environment:
         - HTTP_PROXY=http://<proxy.address>:<port>
         - HTTPS_PROXY=http://<proxy.address>:<port>
```
:::

:::{tab-item} Kubernetes pod manifest
```yaml
env:
   - name: HTTP_PROXY
     value: '<proxy.address>:<port>'
   - name: HTTPS_PROXY
     value: '<proxy.address>:<port>'
```
:::

:::{tab-item} systemmd [Service] unit file
```
[Service]
Environment="HTTP_PROXY=http://<proxy.address>:<port>"
Environment="HTTPS_PROXY=http://<proxy.address>:<port>"
Environment="NO_PROXY=<address1>,<address2>"
```
:::

::::

:::{{note}}
For the {{agent}}, proxy support applies to all exporters, including those using gRPC. No special configuration is needed beyond the environment variables.

If you're using an SDK that doesn't support proxy variables directly, consider routing telemetry through the {{agent}} configured with proxy settings. This ensures consistent proxy handling. For more information, refer to [Proxy settings for Elastic OTel SDKs](docs-content://troubleshoot/ingest/opentelemetry/edot-sdks/proxy.md).
:::


## Resources

[Proxy support - contrib documentation](https://opentelemetry.io/docs/collector/configuration/#proxy-support)
