---
title: Download the EDOT Collector
description: Direct download links for EDOT Collector binaries for various operating systems and architectures.
url: https://docs-v3-preview.elastic.dev/reference/edot-collector/download
products:
  - Elastic Agent
  - Elastic Cloud Serverless
  - Elastic Distribution of OpenTelemetry Collector
  - Elastic Observability
---

# Download the EDOT Collector

The Elastic Distribution of OpenTelemetry (EDOT) Collector is embedded in the Elastic Agent package as a separate binary that invokes OpenTelemetry Collector components.
The following table contains direct download links for the latest EDOT Collector version for different operating systems and architectures.

| Platform    | Architecture | Download link                                                                                                                              |
|-------------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Windows     | x86_64       | [Download (Zip)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-windows-x86_64.zip)Download (Zip)          |
| macOS       | x86_64       | [Download (Tar.gz)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-darwin-x86_64.tar.gz)Download (Tar.gz)  |
| macOS       | aarch64      | [Download (Tar.gz)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-darwin-aarch64.tar.gz)Download (Tar.gz) |
| Linux       | x86_64       | [Download (Tar.gz)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-linux-x86_64.tar.gz)Download (Tar.gz)   |
| Linux       | aarch64      | [Download (Tar.gz)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-linux-arm64.tar.gz)Download (Tar.gz)    |
| Linux (DEB) | x86_64       | [Download (Deb)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-amd64.deb)Download (Deb)                   |
| Linux (DEB) | aarch64      | [Download (Deb)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-arm64.deb)Download (Deb)                   |
| Linux (RPM) | x86_64       | [Download (Rpm)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-x86_64.rpm)Download (Rpm)                  |
| Linux (RPM) | aarch64      | [Download (Rpm)](https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-aarch64.rpm)Download (Rpm)                 |

After you've downloaded and uncompressed the file, you can get EDOT Collector running with the following command:
```
sudo ./otelcol --config otel.yml
```

For specific configuration, refer to the [Quickstart guides](https://docs-v3-preview.elastic.dev/elastic/docs-content/tree/main/solutions/observability/get-started/opentelemetry/quickstart) or refer to [Configuration](https://docs-v3-preview.elastic.dev/reference/edot-collector/config/).