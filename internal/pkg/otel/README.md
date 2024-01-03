# Elastic Distribution for OpenTelemetry Collector

This is an Elastic supported distribution of the [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector).

## Running Elastic OpenTelemetry Distribution

To run Elastic OpenTelemetry Distribution you can use Elastic-Agent binary downloaded for your OS and architecture. 
Running command 

```bash
./elastic-agent -c otel.yml run
```

from unpacked Elastic Agent package will run Elastic-Agent as a Distro. `-c` flag needs to point to [OpenTelemetry Collector Configuration file](https://opentelemetry.io/docs/collector/configuration/) named `otel`, `otlp` or `otelcol`.
Both `yaml` and `yml` suffixes are supported. 

> In case this condition is not met, Elastic Agent will run in its default mode and will not behave as OpenTelemetry Collector.

Note that `validate` subcommand and `feature gates` are not supported yet.

## Components

This sections provides a summary of components included in Elastic OpenTelemetry Collector distribution.

### Receivers

| Dependency | Version |
|---|---|
| github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver | v0.89.0|
| go.opentelemetry.io/collector/receiver/otlpreceiver | v0.89.0|


### Exporters

| Dependency | Version |
|---|---|
| github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter | v0.89.0|
| go.opentelemetry.io/collector/exporter/debugexporter | v0.89.0|
| go.opentelemetry.io/collector/exporter/otlpexporter | v0.89.0|


### Processors

| Dependency | Version |
|---|---|
| github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor | v0.89.0|
| github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor | v0.89.0|
| github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor | v0.89.0|
| go.opentelemetry.io/collector/processor/batchprocessor | v0.89.0|
| go.opentelemetry.io/collector/processor/memorylimiterprocessor | v0.89.0|
