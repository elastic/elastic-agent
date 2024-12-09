# Elastic Distribution for OpenTelemetry Collector

This is an Elastic supported distribution of the [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector).

## Running the Elastic Distribution for OpenTelemetry Collector

To run the Elastic Distribution for OpenTelemetry Collector you can use Elastic-Agent binary downloaded for your OS and architecture.
Running command

```bash
./elastic-agent otel --config otel.yml
```

from unpacked Elastic Agent package will run Elastic-Agent as an OpenTelemetry Collector. The `--config` flag needs to point to [OpenTelemetry Collector Configuration file](https://opentelemetry.io/docs/collector/configuration/). OTel mode is available only using `otel` subcommand. Elastic Agent will not do any autodetection of configuration file passed when used without `otel` subcommand and will try to run normally.

To validate OTel configuration run `otel validate` subcommand:

```bash
./elastic-agent otel validate --config otel.yml
```

[feature gates](https://github.com/open-telemetry/opentelemetry-collector/blob/main/featuregate/README.md#controlling-gates) are supported using `--feature-gates` flag.

## Components

This section provides a summary of components included in the Elastic Distribution for OpenTelemetry Collector.

### Receivers

| Component | Version |
|---|---|
<<<<<<< HEAD
| [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/jaegerreceiver/v0.114.0/receiver/jaegerreceiver/README.md) | v0.114.0 |
| [prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/prometheusreceiver/v0.114.0/receiver/prometheusreceiver/README.md) | v0.114.0 |
| [zipkinreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/zipkinreceiver/v0.114.0/receiver/zipkinreceiver/README.md) | v0.114.0 |
| [filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/filelogreceiver/v0.114.0/receiver/filelogreceiver/README.md) | v0.114.0 |
| [hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/hostmetricsreceiver/v0.114.0/receiver/hostmetricsreceiver/README.md) | v0.114.0 |
| [httpcheckreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/httpcheckreceiver/v0.114.0/receiver/httpcheckreceiver/README.md) | v0.114.0 |
| [k8sclusterreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sclusterreceiver/v0.114.0/receiver/k8sclusterreceiver/README.md) | v0.114.0 |
| [k8sobjectsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sobjectsreceiver/v0.114.0/receiver/k8sobjectsreceiver/README.md) | v0.114.0 |
| [kubeletstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/kubeletstatsreceiver/v0.114.0/receiver/kubeletstatsreceiver/README.md) | v0.114.0 |
| [otlpreceiver](https://github.com/open-telemetry/opentelemetry-collector/blob/receiver/otlpreceiver/v0.114.0/receiver/otlpreceiver/README.md) | v0.114.0 |
=======
| [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/jaegerreceiver/v0.115.0/receiver/jaegerreceiver/README.md) | v0.115.0 |
| [prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/prometheusreceiver/v0.115.0/receiver/prometheusreceiver/README.md) | v0.115.0 |
| [zipkinreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/zipkinreceiver/v0.115.0/receiver/zipkinreceiver/README.md) | v0.115.0 |
| [filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/filelogreceiver/v0.115.0/receiver/filelogreceiver/README.md) | v0.115.0 |
| [hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/hostmetricsreceiver/v0.115.0/receiver/hostmetricsreceiver/README.md) | v0.115.0 |
| [httpcheckreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/httpcheckreceiver/v0.115.0/receiver/httpcheckreceiver/README.md) | v0.115.0 |
| [k8sclusterreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sclusterreceiver/v0.115.0/receiver/k8sclusterreceiver/README.md) | v0.115.0 |
| [k8sobjectsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sobjectsreceiver/v0.115.0/receiver/k8sobjectsreceiver/README.md) | v0.115.0 |
| [kubeletstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/kubeletstatsreceiver/v0.115.0/receiver/kubeletstatsreceiver/README.md) | v0.115.0 |
| [otlpreceiver](https://github.com/open-telemetry/opentelemetry-collector/blob/receiver/otlpreceiver/v0.115.0/receiver/otlpreceiver/README.md) | v0.115.0 |
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))

### Exporters

| Component | Version |
|---|---|
<<<<<<< HEAD
| [elasticsearchexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/elasticsearchexporter/v0.114.0/exporter/elasticsearchexporter/README.md) | v0.114.0 |
| [fileexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/fileexporter/v0.114.0/exporter/fileexporter/README.md) | v0.114.0 |
| [debugexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/debugexporter/v0.114.0/exporter/debugexporter/README.md) | v0.114.0 |
| [otlpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlpexporter/v0.114.0/exporter/otlpexporter/README.md) | v0.114.0 |
| [otlphttpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlphttpexporter/v0.114.0/exporter/otlphttpexporter/README.md) | v0.114.0 |
=======
| [elasticsearchexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/elasticsearchexporter/v0.115.0/exporter/elasticsearchexporter/README.md) | v0.115.0 |
| [fileexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/fileexporter/v0.115.0/exporter/fileexporter/README.md) | v0.115.0 |
| [debugexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/debugexporter/v0.115.0/exporter/debugexporter/README.md) | v0.115.0 |
| [otlpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlpexporter/v0.115.0/exporter/otlpexporter/README.md) | v0.115.0 |
| [otlphttpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlphttpexporter/v0.115.0/exporter/otlphttpexporter/README.md) | v0.115.0 |
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))

### Processors

| Component | Version |
|---|---|
| [elasticinframetricsprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/elasticinframetricsprocessor/v0.13.0/processor/elasticinframetricsprocessor/README.md) | v0.13.0 |
| [elastictraceprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/elastictraceprocessor/v0.3.0/processor/elastictraceprocessor/README.md) | v0.3.0 |
| [lsmintervalprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/lsmintervalprocessor/v0.3.0/processor/lsmintervalprocessor/README.md) | v0.3.0 |
<<<<<<< HEAD
| [memorylimiterprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/memorylimiterprocessor/v0.114.0/processor/memorylimiterprocessor/README.md) | v0.114.0 |
| [attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/attributesprocessor/v0.114.0/processor/attributesprocessor/README.md) | v0.114.0 |
| [filterprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/filterprocessor/v0.114.0/processor/filterprocessor/README.md) | v0.114.0 |
| [k8sattributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/k8sattributesprocessor/v0.114.0/processor/k8sattributesprocessor/README.md) | v0.114.0 |
| [resourcedetectionprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourcedetectionprocessor/v0.114.0/processor/resourcedetectionprocessor/README.md) | v0.114.0 |
| [resourceprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourceprocessor/v0.114.0/processor/resourceprocessor/README.md) | v0.114.0 |
| [transformprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/transformprocessor/v0.114.0/processor/transformprocessor/README.md) | v0.114.0 |
| [batchprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/batchprocessor/v0.114.0/processor/batchprocessor/README.md) | v0.114.0 |
=======
| [memorylimiterprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/memorylimiterprocessor/v0.115.0/processor/memorylimiterprocessor/README.md) | v0.115.0 |
| [attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/attributesprocessor/v0.115.0/processor/attributesprocessor/README.md) | v0.115.0 |
| [filterprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/filterprocessor/v0.115.0/processor/filterprocessor/README.md) | v0.115.0 |
| [k8sattributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/k8sattributesprocessor/v0.115.0/processor/k8sattributesprocessor/README.md) | v0.115.0 |
| [resourcedetectionprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourcedetectionprocessor/v0.115.0/processor/resourcedetectionprocessor/README.md) | v0.115.0 |
| [resourceprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourceprocessor/v0.115.0/processor/resourceprocessor/README.md) | v0.115.0 |
| [transformprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/transformprocessor/v0.115.0/processor/transformprocessor/README.md) | v0.115.0 |
| [batchprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/batchprocessor/v0.115.0/processor/batchprocessor/README.md) | v0.115.0 |
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))

### Extensions

| Component | Version |
|---|---|
<<<<<<< HEAD
| [healthcheckextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/healthcheckextension/v0.114.0/extension/healthcheckextension/README.md) | v0.114.0 |
| [pprofextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/pprofextension/v0.114.0/extension/pprofextension/README.md) | v0.114.0 |
| [filestorage](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/storage/filestorage/v0.114.0/extension/storage/filestorage/README.md) | v0.114.0 |
| [memorylimiterextension](https://github.com/open-telemetry/opentelemetry-collector/blob/extension/memorylimiterextension/v0.114.0/extension/memorylimiterextension/README.md) | v0.114.0 |
=======
| [healthcheckextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/healthcheckextension/v0.115.0/extension/healthcheckextension/README.md) | v0.115.0 |
| [pprofextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/pprofextension/v0.115.0/extension/pprofextension/README.md) | v0.115.0 |
| [filestorage](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/storage/filestorage/v0.115.0/extension/storage/filestorage/README.md) | v0.115.0 |
| [memorylimiterextension](https://github.com/open-telemetry/opentelemetry-collector/blob/extension/memorylimiterextension/v0.115.0/extension/memorylimiterextension/README.md) | v0.115.0 |
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))

### Connectors

| Component | Version |
|---|---|
| [signaltometricsconnector](https://github.com/elastic/opentelemetry-collector-components/blob/connector/signaltometricsconnector/v0.3.0/connector/signaltometricsconnector/README.md) | v0.3.0 |
<<<<<<< HEAD
| [routingconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/routingconnector/v0.114.0/connector/routingconnector/README.md) | v0.114.0 |
| [spanmetricsconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/spanmetricsconnector/v0.114.0/connector/spanmetricsconnector/README.md) | v0.114.0 |
=======
| [routingconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/routingconnector/v0.115.0/connector/routingconnector/README.md) | v0.115.0 |
| [spanmetricsconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/spanmetricsconnector/v0.115.0/connector/spanmetricsconnector/README.md) | v0.115.0 |
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
## Persistence in OpenTelemetry Collector

By default, the OpenTelemetry Collector is stateless, which means it doesn't store offsets on disk while reading files. As a result, if you restart the collector, it won't retain the last read offset, potentially leading to data duplication or loss. However, we have configured persistence in the settings provided with the Elastic Agent package. 

To enable persistence for the `filelogreceiver`, we add the `file_storage` extension and activate it for `filelog`. 
Execute `export STATE_PATH=/path/to/store/otel/offsets` and use the following configuration to enable persistence:

```yaml
receivers:
  filelog/platformlogs:
    include: [ /var/log/system.log ]
    start_at: beginning
    storage: file_storage/filelogreceiver
extensions:
  file_storage/filelogreceiver:
    directory: ${env:STATE_PATH}
    create_directory: true
exporters:
  ...
processors:
  ...
service:
  extensions: [file_storage]
  pipelines:
    logs/platformlogs:
      receivers: [filelog/platformlogs]
      processors: [...]
      exporters: [...]
```

> [!WARNING]  
Removing the storage key from the filelog section will disable persistence, which will lead to data duplication or loss when the collector restarts.

> [!IMPORTANT]  
If you remove the `create_directory: true` option, you'll need to manually create a directory to store the data. You can ignore this option if the directory already exists.

### Persistence in standalone Docker mode

By default, when running Elastic Distribution for OpenTelemetry Collector in Docker, checkpoints are stored in `/usr/share/elastic-agent/otel_registry` by default. To ensure data persists across container restarts, you can use the following command:

```bash
docker run --rm -ti --entrypoint="elastic-agent" --mount type=bind,source=/path/on/host,target=/usr/share/elastic-agent/otel_registry  docker.elastic.co/beats/elastic-agent:9.0.0-SNAPSHOT otel
```

### Known issues:
-  You face following `failed to build extensions: failed to create extension "file_storage/filelogreceiver": mkdir ...: permission denied` error while running the otel mode
	- Cause: This issue is likely because the user running the executable lacks sufficient permissions to create the directory.
	- Resolution: You can either create the directory manually or specify a path with necessary permissions.
