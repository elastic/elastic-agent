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

Use the components command to get the list of components included in the binary:

```bash
./elastic-agent otel components
```

[feature gates](https://github.com/open-telemetry/opentelemetry-collector/blob/main/featuregate/README.md#controlling-gates) are supported using `--feature-gates` flag.

## Components

This section provides a summary of components included in the Elastic Distribution for OpenTelemetry Collector.

### Receivers

| Component | Version |
|---|---|
| [apachereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/apachereceiver/v0.144.0/receiver/apachereceiver/README.md) | v0.144.0 |
| [awss3receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/awss3receiver/v0.144.0/receiver/awss3receiver/README.md) | v0.144.0 |
| [dockerstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/dockerstatsreceiver/v0.144.0/receiver/dockerstatsreceiver/README.md) | v0.144.0 |
| [elasticapmintakereceiver](https://github.com/elastic/opentelemetry-collector-components/blob/receiver/elasticapmintakereceiver/v0.29.0/receiver/elasticapmintakereceiver/README.md) | v0.29.0 |
| [filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/filelogreceiver/v0.144.0/receiver/filelogreceiver/README.md) | v0.144.0 |
| [hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/hostmetricsreceiver/v0.144.0/receiver/hostmetricsreceiver/README.md) | v0.144.0 |
| [httpcheckreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/httpcheckreceiver/v0.144.0/receiver/httpcheckreceiver/README.md) | v0.144.0 |
| [iisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/iisreceiver/v0.144.0/receiver/iisreceiver/README.md) | v0.144.0 |
| [jaegerreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/jaegerreceiver/v0.144.0/receiver/jaegerreceiver/README.md) | v0.144.0 |
| [jmxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/jmxreceiver/v0.144.0/receiver/jmxreceiver/README.md) | v0.144.0 |
| [k8sclusterreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sclusterreceiver/v0.144.0/receiver/k8sclusterreceiver/README.md) | v0.144.0 |
| [k8seventsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8seventsreceiver/v0.144.0/receiver/k8seventsreceiver/README.md) | v0.144.0 |
| [k8sobjectsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/k8sobjectsreceiver/v0.144.0/receiver/k8sobjectsreceiver/README.md) | v0.144.0 |
| [kafkareceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/kafkareceiver/v0.144.0/receiver/kafkareceiver/README.md) | v0.144.0 |
| [kubeletstatsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/kubeletstatsreceiver/v0.144.0/receiver/kubeletstatsreceiver/README.md) | v0.144.0 |
| [mysqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/mysqlreceiver/v0.144.0/receiver/mysqlreceiver/README.md) | v0.144.0 |
| [nginxreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/nginxreceiver/v0.144.0/receiver/nginxreceiver/README.md) | v0.144.0 |
| [nopreceiver](https://github.com/open-telemetry/opentelemetry-collector/blob/receiver/nopreceiver/v0.144.0/receiver/nopreceiver/README.md) | v0.144.0 |
| [otlpreceiver](https://github.com/open-telemetry/opentelemetry-collector/blob/receiver/otlpreceiver/v0.144.0/receiver/otlpreceiver/README.md) | v0.144.0 |
| [postgresqlreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/postgresqlreceiver/v0.144.0/receiver/postgresqlreceiver/README.md) | v0.144.0 |
| [profiling](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/blob/v0.0.202601/README.md) | v0.0.202601 |
| [prometheusreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/prometheusreceiver/v0.144.0/receiver/prometheusreceiver/README.md) | v0.144.0 |
| [prometheusremotewritereceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/prometheusremotewritereceiver/v0.144.0/receiver/prometheusremotewritereceiver/README.md) | v0.144.0 |
| [receivercreator](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/receivercreator/v0.144.0/receiver/receivercreator/README.md) | v0.144.0 |
| [redisreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/redisreceiver/v0.144.0/receiver/redisreceiver/README.md) | v0.144.0 |
| [snmpreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/snmpreceiver/v0.144.0/receiver/snmpreceiver/README.md) | v0.144.0 |
| [sqlserverreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/sqlserverreceiver/v0.144.0/receiver/sqlserverreceiver/README.md) | v0.144.0 |
| [windowseventlogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/windowseventlogreceiver/v0.144.0/receiver/windowseventlogreceiver/README.md) | v0.144.0 |
| [windowsperfcountersreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/windowsperfcountersreceiver/v0.144.0/receiver/windowsperfcountersreceiver/README.md) | v0.144.0 |
| [zipkinreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/receiver/zipkinreceiver/v0.144.0/receiver/zipkinreceiver/README.md) | v0.144.0 |

### Exporters

| Component | Version |
|---|---|
| [debugexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/debugexporter/v0.144.0/exporter/debugexporter/README.md) | v0.144.0 |
| [elasticsearchexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/elasticsearchexporter/v0.144.0/exporter/elasticsearchexporter/README.md) | v0.144.0 |
| [fileexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/fileexporter/v0.144.0/exporter/fileexporter/README.md) | v0.144.0 |
| [kafkaexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/kafkaexporter/v0.144.0/exporter/kafkaexporter/README.md) | v0.144.0 |
| [loadbalancingexporter](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/exporter/loadbalancingexporter/v0.144.0/exporter/loadbalancingexporter/README.md) | v0.144.0 |
| [nopexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/nopexporter/v0.144.0/exporter/nopexporter/README.md) | v0.144.0 |
| [otlpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlpexporter/v0.144.0/exporter/otlpexporter/README.md) | v0.144.0 |
| [otlphttpexporter](https://github.com/open-telemetry/opentelemetry-collector/blob/exporter/otlphttpexporter/v0.144.0/exporter/otlphttpexporter/README.md) | v0.144.0 |

### Processors

| Component | Version |
|---|---|
| [attributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/attributesprocessor/v0.144.0/processor/attributesprocessor/README.md) | v0.144.0 |
| [batchprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/batchprocessor/v0.144.0/processor/batchprocessor/README.md) | v0.144.0 |
| [cumulativetodeltaprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/cumulativetodeltaprocessor/v0.144.0/processor/cumulativetodeltaprocessor/README.md) | v0.144.0 |
| [elasticapmprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/elasticapmprocessor/v0.29.0/processor/elasticapmprocessor/README.md) | v0.29.0 |
| [elasticinframetricsprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/elasticinframetricsprocessor/v0.29.0/processor/elasticinframetricsprocessor/README.md) | v0.29.0 |
| [elastictraceprocessor](https://github.com/elastic/opentelemetry-collector-components/blob/processor/elastictraceprocessor/v0.29.0/processor/elastictraceprocessor/README.md) | v0.29.0 |
| [filterprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/filterprocessor/v0.144.0/processor/filterprocessor/README.md) | v0.144.0 |
| [geoipprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/geoipprocessor/v0.144.0/processor/geoipprocessor/README.md) | v0.144.0 |
| [k8sattributesprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/k8sattributesprocessor/v0.144.0/processor/k8sattributesprocessor/README.md) | v0.144.0 |
| [memorylimiterprocessor](https://github.com/open-telemetry/opentelemetry-collector/blob/processor/memorylimiterprocessor/v0.144.0/processor/memorylimiterprocessor/README.md) | v0.144.0 |
| [resourcedetectionprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourcedetectionprocessor/v0.144.0/processor/resourcedetectionprocessor/README.md) | v0.144.0 |
| [resourceprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/resourceprocessor/v0.144.0/processor/resourceprocessor/README.md) | v0.144.0 |
| [tailsamplingprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/tailsamplingprocessor/v0.144.0/processor/tailsamplingprocessor/README.md) | v0.144.0 |
| [transformprocessor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/processor/transformprocessor/v0.144.0/processor/transformprocessor/README.md) | v0.144.0 |

### Extensions

| Component | Version |
|---|---|
| [apikeyauthextension](https://github.com/elastic/opentelemetry-collector-components/blob/extension/apikeyauthextension/v0.29.0/extension/apikeyauthextension/README.md) | v0.29.0 |
| [apmconfigextension](https://github.com/elastic/opentelemetry-collector-components/blob/extension/apmconfigextension/v0.29.0/extension/apmconfigextension/README.md) | v0.29.0 |
| [awslogsencodingextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/encoding/awslogsencodingextension/v0.144.0/extension/encoding/awslogsencodingextension/README.md) | v0.144.0 |
| [bearertokenauthextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/bearertokenauthextension/v0.144.0/extension/bearertokenauthextension/README.md) | v0.144.0 |
| [filestorage](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/storage/filestorage/v0.144.0/extension/storage/filestorage/README.md) | v0.144.0 |
| [headerssetterextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/headerssetterextension/v0.144.0/extension/headerssetterextension/README.md) | v0.144.0 |
| [healthcheckextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/healthcheckextension/v0.144.0/extension/healthcheckextension/README.md) | v0.144.0 |
| [healthcheckv2extension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/healthcheckv2extension/v0.144.0/extension/healthcheckv2extension/README.md) | v0.144.0 |
| [k8sleaderelector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/k8sleaderelector/v0.144.0/extension/k8sleaderelector/README.md) | v0.144.0 |
| [k8sobserver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/observer/k8sobserver/v0.144.0/extension/observer/k8sobserver/README.md) | v0.144.0 |
| [memorylimiterextension](https://github.com/open-telemetry/opentelemetry-collector/blob/extension/memorylimiterextension/v0.144.0/extension/memorylimiterextension/README.md) | v0.144.0 |
| [pprofextension](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/extension/pprofextension/v0.144.0/extension/pprofextension/README.md) | v0.144.0 |

### Connectors

| Component | Version |
|---|---|
| [elasticapmconnector](https://github.com/elastic/opentelemetry-collector-components/blob/connector/elasticapmconnector/v0.29.0/connector/elasticapmconnector/README.md) | v0.29.0 |
| [forwardconnector](https://github.com/open-telemetry/opentelemetry-collector/blob/connector/forwardconnector/v0.144.0/connector/forwardconnector/README.md) | v0.144.0 |
| [profilingmetricsconnector](https://github.com/elastic/opentelemetry-collector-components/blob/connector/profilingmetricsconnector/v0.29.0/connector/profilingmetricsconnector/README.md) | v0.29.0 |
| [routingconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/routingconnector/v0.144.0/connector/routingconnector/README.md) | v0.144.0 |
| [spanmetricsconnector](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/connector/spanmetricsconnector/v0.144.0/connector/spanmetricsconnector/README.md) | v0.144.0 |
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
docker run --rm -ti --entrypoint="elastic-agent" --mount type=bind,source=/path/on/host,target=/usr/share/elastic-agent/otel_registry  docker.elastic.co/elastic-agent/elastic-agent:9.0.0-SNAPSHOT otel
```

### Known issues:
-  You face following `failed to build extensions: failed to create extension "file_storage/filelogreceiver": mkdir ...: permission denied` error while running the otel mode
	- Cause: This issue is likely because the user running the executable lacks sufficient permissions to create the directory.
	- Resolution: You can either create the directory manually or specify a path with necessary permissions.
