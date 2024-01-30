# Elastic Distribution for OpenTelemetry Collector

This is an Elastic supported distribution of the [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector).

## Running the Elastic Distribution for OpenTelemetry Collector

To run the Elastic Distribution for OpenTelemetry Collector you can use Elastic-Agent binary downloaded for your OS and architecture. 
Running command 

```bash
./elastic-agent -c otel.yml run
```

from unpacked Elastic Agent package will run Elastic-Agent as an OpenTelemetry Collector. The `-c` flag needs to point to [OpenTelemetry Collector Configuration file](https://opentelemetry.io/docs/collector/configuration/) named `otel`, `otlp` or `otelcol`.
Both `yaml` and `yml` suffixes are supported. 

> In case this condition is not met, Elastic Agent will run in its default mode and will not behave as OpenTelemetry Collector.

Note that `validate` subcommand and [feature gates](https://github.com/open-telemetry/opentelemetry-collector/blob/main/featuregate/README.md#controlling-gates) are not supported yet.

## Components

This section provides a summary of components included in the Elastic Distribution for OpenTelemetry Collector.


### Receivers

| Component | Version |
|---|---|
| filelogreceiver | v0.93.0|
| otlpreceiver | v0.93.0|




### Exporters

| Component | Version |
|---|---|
| fileexporter | v0.93.0|
| debugexporter | v0.93.0|
| otlpexporter | v0.93.0|




### Processors

| Component | Version |
|---|---|
| attributesprocessor | v0.93.0|
| resourceprocessor | v0.93.0|
| transformprocessor | v0.93.0|
| batchprocessor | v0.93.0|
| memorylimiterprocessor | v0.93.0|



