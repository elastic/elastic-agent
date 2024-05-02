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
| filelogreceiver | v0.98.0|
| otlpreceiver | v0.96.0|
=======
| filelogreceiver | v0.97.0|
| otlpreceiver | v0.97.0|
>>>>>>> a3900f0324 (Use otel version 0.97.0 (#4638))




### Exporters

| Component | Version |
|---|---|
<<<<<<< HEAD
| fileexporter | v0.98.0|
| debugexporter | v0.96.0|
| otlpexporter | v0.96.0|
=======
| fileexporter | v0.97.0|
| debugexporter | v0.97.0|
| otlpexporter | v0.97.0|
>>>>>>> a3900f0324 (Use otel version 0.97.0 (#4638))




### Processors

| Component | Version |
|---|---|
<<<<<<< HEAD
| attributesprocessor | v0.98.0|
| resourceprocessor | v0.98.0|
| transformprocessor | v0.98.0|
| batchprocessor | v0.96.0|
| memorylimiterprocessor | v0.96.0|
=======
| attributesprocessor | v0.97.0|
| resourceprocessor | v0.97.0|
| transformprocessor | v0.97.0|
| batchprocessor | v0.97.0|
| memorylimiterprocessor | v0.97.0|
>>>>>>> a3900f0324 (Use otel version 0.97.0 (#4638))



