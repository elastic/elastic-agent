---
title: Configure proxy settings for EDOT components
description: Configuration of the EDOT Collector's proxy settings.
url: https://docs-v3-preview.elastic.dev/reference/edot-collector/config/proxy
products:
  - Elastic Agent
  - Elastic Cloud Serverless
  - Elastic Distribution of OpenTelemetry Collector
  - Elastic Observability
---

# Configure proxy settings for EDOT components

When running Elastic Distributions of OpenTelemetry (EDOT) in environments that require outbound traffic to go through a proxy, you must explicitly configure proxy settings.
You may need to configure a proxy if:
- Your app is deployed behind a corporate proxy or firewall.
- Your telemetry is sent to Elastic APM in Elastic Cloud or another hosted destination.
- Network errors such as `Connection timed out` or `SSL handshake failed` appear in logs.


## Available proxy variables


| Variable    | Description                                |
|-------------|--------------------------------------------|
| HTTP_PROXY  | URL of the proxy server for HTTP requests  |
| HTTPS_PROXY | URL of the proxy server for HTTPS requests |
| NO_PROXY    | Comma-separated list of hosts to exclude   |


## Configure proxy settings for the EDOT Collector

Most EDOT components honor common proxy environment variables. The following examples show how to configure them:
<tab-set>

  <tab-item title="Docker run">

    ```bash
    docker run -e HTTP_PROXY=http://<proxy.address>:<port> \
               -e HTTPS_PROXY=http://<proxy.address>:<port> \
    	        otel/opentelemetry-collector:latest
    ```
  </tab-item>

  <tab-item title="Docker compose">

    ```yaml
    services:
       edotcollector:
          environment:
             - HTTP_PROXY=http://<proxy.address>:<port>
             - HTTPS_PROXY=http://<proxy.address>:<port>
    ```
  </tab-item>

  <tab-item title="Kubernetes pod manifest">

    ```yaml
    env:
       - name: HTTP_PROXY
         value: '<proxy.address>:<port>'
       - name: HTTPS_PROXY
         value: '<proxy.address>:<port>'
    ```
  </tab-item>

  <tab-item title="systemmd [Service] unit file">

    ```
    [Service]
    Environment="HTTP_PROXY=http://<proxy.address>:<port>"
    Environment="HTTPS_PROXY=http://<proxy.address>:<port>"
    Environment="NO_PROXY=<address1>,<address2>"
    ```
  </tab-item>
</tab-set>

<note>
  For the EDOT Collector, proxy support applies to all exporters, including those using gRPC. No special configuration is needed beyond the environment variables.If you're using an SDK that doesn't support proxy variables directly, consider routing telemetry through an EDOT Collector configured with proxy settings. This ensures consistent proxy handling. For more information, refer to [Proxy settings for EDOT SDKs](https://docs-v3-preview.elastic.dev/elastic/opentelemetry/tree/main/reference/edot-sdks/proxyproxy).
</note>


## Resources

[Proxy support - contrib documentation](https://opentelemetry.io/docs/collector/configuration/#proxy-support)