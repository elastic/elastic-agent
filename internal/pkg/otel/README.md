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
| filelogreceiver | v0.104.0|
| hostmetricsreceiver | v0.104.0|
| httpcheckreceiver | v0.104.0|
| k8sclusterreceiver | v0.104.0|
| kubeletstatsreceiver | v0.104.0|
| otlpreceiver | v0.104.0|




### Exporters

| Component | Version |
|---|---|
| elasticsearchexporter | v0.104.0|
| fileexporter | v0.104.0|
| debugexporter | v0.104.0|
| otlpexporter | v0.104.0|
| otlphttpexporter | v0.104.0|




### Processors

| Component | Version |
|---|---|
| elasticinframetricsprocessor | v0.5.1|
| attributesprocessor | v0.104.0|
| filterprocessor | v0.104.0|
| k8sattributesprocessor | v0.104.0|
| resourcedetectionprocessor | v0.104.0|
| resourceprocessor | v0.104.0|
| transformprocessor | v0.104.0|
| batchprocessor | v0.104.0|




### Extensions

| Component | Version |
|---|---|
| storage/filestorage | v0.104.0|
| memorylimiterextension | v0.104.0|




### Connectors

| Component | Version |
|---|---|
| spanmetricsconnector | v0.104.0|

