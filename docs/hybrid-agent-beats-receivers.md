# Hybrid Agent and Beats Receivers

This page provides a brief overview of the Beat receivers and Hybrid Agent projects and how to experiment with them.
These are part of Elastic's larger effort to base data collection on OpenTelemetry technologies. For more context, see
https://www.elastic.co/observability-labs/blog/elastic-agent-pivot-opentelemetry. This document does not aim to be a
comprehensive explanation of beat receivers or hybrid agent as concepts, it is only a brief overview along with
testing instructions. Beat receivers and hybrid agent capabilities are available starting with the 9.1.0 and 8.19.0
releases at a technical preview level and are not enabled or used by default.

## Beat Receivers

**Beat Receivers** are beat inputs and processors executing as a receiver in an OpenTelemetry collector pipeline.
Beat receivers are designed to output the exact same data they do today, and do not output data in the OTLP schema.

Beat receivers will eventually be the default execution mode for Beat inputs in an elastic-agent.yml file (whether
written by hand or generated via Fleet). Elastic Agent will automatically translate the relevant parts of it's
elastic-agent.yml file into OpenTelemetry collector configurations and execute them in the collector. This capability
is currently gated by a feature flag.

### Beat Receivers for Agent Monitoring

The first part of the Elastic Agent configuration that will run as Beat receivers
by default will be the self-monitoring functionality. To use Beat receivers for self-monitoring set the
`_runtime_experimental: "otel"` feature flag in the `agent.monitoring` section of the configuration:

```yaml
agent.monitoring:
  enabled: true
  logs: true
  metrics: true
  _runtime_experimental: otel
```

This setting will be available as a toggle in the Fleet UI as part of the agent policy advanced settings once
https://github.com/elastic/kibana/issues/233186 is implemented. Before that change is implemented, the agent policy
overrides API can be used to add `_runtime_experimental: "otel"` to the `agent.monitoring` section of the policy.
See https://support.elastic.dev/knowledge/view/06b69893 for details on the policy overrides API.

For the Elastic Agent container images, the `AGENT_MONITORING_RUNTIME_EXPERIMENTAL` environment variable can be set to either `process` or `otel` to override the default runtime used for agent monitoring.

Executing the `elastic-agent diagnostics` command in this mode will now produce an `otel-final.yml` file showing the generated
collector configuration used to run the Beat receivers.

### Beat Receivers for Data Collection

The capability to use Beat receivers is being enabled on per Beat and per input type basis. At the time of writing (August 2025),
Filebeat and Metricbeat can run as receivers and both the `filestream` and `system/metrics` inputs work outside of
monitoring use cases. An example showing how to set the feature flag to run the `filestream` and `system/metrics` inputs as Beat
receivers follows below.

```yaml
inputs:
  - id: system-metrics-receiver
    type: system/metrics
    _runtime_experimental: otel
    streams:
      - metricsets:
        - cpu
        data_stream.dataset: system.cpu
  - id: filestream-receiver
    type: filestream
    _runtime_experimental: otel
    data_stream.dataset: generic
    paths:
        - /var/log/*.log
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
```

## Hybrid Agent

**Hybrid Agent** refers the capability of Elastic Agent to run OpenTelemetry collector pipelines specified directly in
it's elastic-agent.yml file. This allows running Beat based ECS data collection alongside OTLP native data collection in
the same agent. The diagram below shows the end state of the Elastic Agent where both Beats (via Beat receivers) and OpenTelemetry
collector receivers run in the same collector process.

![Hybrid Agent](images/hybrid-agent.png)

A runnable Hybrid agent example configuration follows below.

```yaml
agent.monitoring:
  enabled: true
  logs: true
  metrics: true

outputs:
  default:
    type: elasticsearch
    hosts: [127.0.0.1:9200]
    api_key: "example-key"
    preset: balanced

inputs:
  - id: filestream-system-66cab0a6-6fa3-46b1-9af1-2ea171fbd887
    type: filestream
    # _runtime_experimental: otel # Optional - also run the filestream input as a collector receiver.
    data_stream:
      namespace: default
    streams:
      - id: filestream-system.auth-66cab0a6-6fa3-46b1-9af1-2ea171fbd887
        data_stream:
          dataset: system.auth
        paths:
          - /var/log/auth*.log

receivers:
  httpcheck/httpcheck-6d24bb0d-5349-4714-a7ea-2988abcb928b:
    collection_interval: 30s
    targets:
      - method: "GET"
        endpoints:
            - https://example.com

processors:
  transform/httpcheck-6d24bb0d-5349-4714-a7ea-2988abcb928b:
    metric_statements:
      - delete_key(datapoint.attributes,"http.status_class")

exporters:
  debug/default:
    verbosity: detailed

service:
  pipelines:
    metrics/httpcheck-6d24bb0d-5349-4714-a7ea-2988abcb928b:
      receivers: [httpcheck/httpcheck-6d24bb0d-5349-4714-a7ea-2988abcb928b]
      processors: [transform/httpcheck-6d24bb0d-5349-4714-a7ea-2988abcb928b]
      exporters: [debug/default]
```

## OTel Mode

The elastic agent can also be executed in "Otel mode" by executing the `elastic-agent otel` command. This immediately invokes
the entrypoint of the EDOT OpenTelemetry collector bypassing all other Elastic Agent functionality. In this mode Fleet management is
not available and elastic-agent.yml configurations cannot be executed. Beat receivers are still usable in this mode, but they must be
configured manually like any other receiver.

An example showing how to configure Beat receivers directly in a collector pipeline that will execute with the `elastic-agent otel` command
follows below. The pipeline below is a simplified version of the one generated to run the `filestream` and `system/metrics` inputs as receivers
show earlier.

```yaml
receivers:
    filebeatreceiver:
        filebeat:
            inputs:
                - data_stream:
                    dataset: generic
                  id: filestream-receiver
                  index: logs-generic-default
                  paths:
                    - /var/log/*.log
                  type: filestream
    metricbeatreceiver:
        metricbeat:
            modules:
                - data_stream:
                    dataset: system.cpu
                  index: metrics-system.cpu-default
                  metricsets:
                    - cpu
                  module: system
exporters:
    elasticsearch/_agent-component/default:
        api_key: placeholder
        compression: gzip
        compression_params:
            level: 1
        endpoints:
            - http://localhost:9200
        logs_dynamic_id:
            enabled: true
        mapping:
            mode: bodymap
service:
    pipelines:
        logs:
            exporters:
                - elasticsearch/_agent-component/default
            receivers:
                - filebeatreceiver
                - metricbeatreceiver
```
