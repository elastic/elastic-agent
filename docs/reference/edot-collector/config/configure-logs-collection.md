---
navigation_title: Configure Logs Collection
description: Learn how to configure and customize logs collection through the Elastic Distribution of OpenTelemetry Collector. 
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

# Configure logs collection

Learn how to configure and customize logs collection through the {{edot}} Collector. 

:::{note}
{{es}} Ingest Pipelines are not yet applicable to OTel-native data. Use OTel Collector processing pipelines for pre-processing and parsing of logs.
:::

## Parse JSON logs

You can parse logs that come in JSON format through
[filelog](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/receiver/filelogreceiver/README.md)
receiver's operators. Use the [`router`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/pkg/stanza/docs/operators/router.md) to check if the format is JSON and route the logs to [`json-parser`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/pkg/stanza/docs/operators/json_parser.md). For example:

```yaml
# ...
receivers:
  filelog:
    # ...
    operators:
      # Check if format is json and route properly
      - id: get-format
        routes:
        - expr: body matches "^\\{"
          output: json-parser
        type: router
      # Parse body as JSON https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/stanza/docs/operators/json_parser.md
      - type: json_parser
        id: json-parser
        on_error: send_quiet
        parse_from: body
        parse_to: body

    # ...
```

## Parse multiline logs

You can parse multiline logs using the
[`multiline`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/receiver/filelogreceiver/README.md#multiline-configuration)
option as in the following example:

```yaml
receivers:
  filelog:
    include:
    - /var/log/example/multiline.log
    multiline:
      line_start_pattern: ^Exception
```

The previous configuration can parse the following logs that span across multiple lines and recombine them properly into one single log message:

```
Exception in thread 1 "main" java.lang.NullPointerException
        at com.example.myproject.Book.getTitle(Book.java:16)
        at com.example.myproject.Author.getBookTitles(Author.java:25)
        at com.example.myproject.Bootstrap.main(Bootstrap.java:14)
Exception in thread 2 "main" java.lang.NullPointerException
        at com.example.myproject.Book.getTitle(Book.java:16)
        at com.example.myproject.Author.getBookTitles(Author.java:25)
        at com.example.myproject.Bootstrap.main(Bootstrap.java:44)
```

## Parse OTLP logs in JSON format

You can configure applications instrumented with OpenTelemetry SDKs to write their logs in `OTLP/JSON` format in files stored on disk. The [filelog](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/receiver/filelogreceiver/README.md) receiver can then collect and parse the logs and
forward them to the [`otlpjson`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.123.0/connector/otlpjsonconnector)
connector, which extracts the `OTLP` logs from the `OTLP/JSON` log lines.

An example `OTLP/JSON` log is the following:

```json
{
  "resourceLogs": [
    {
      "resource": {
        "attributes": [
          {
            "key": "deployment.environment.name",
            "value": {
              "stringValue": "staging"
            }
          },
          {
            "key": "service.instance.id",
            "value": {
              "stringValue": "6ad88e10-238c-4fb7-bf97-38df19053366"
            }
          },
          {
            "key": "service.name",
            "value": {
              "stringValue": "checkout"
            }
          },
          {
            "key": "service.namespace",
            "value": {
              "stringValue": "shop"
            }
          },
          {
            "key": "service.version",
            "value": {
              "stringValue": "1.1"
            }
          }
        ]
      },
      "scopeLogs": [
        {
          "scope": {
            "name": "com.mycompany.checkout.CheckoutServiceServer$CheckoutServiceImpl",
            "attributes": []
          },
          "logRecords": [
            {
              "timeUnixNano": "1730435085776869000",
              "observedTimeUnixNano": "1730435085776944000",
              "severityNumber": 9,
              "severityText": "INFO",
              "body": {
                "stringValue": "Order order-12035 successfully placed"
              },
              "attributes": [
                {
                  "key": "customerId",
                  "value": {
                    "stringValue": "customer-49"
                  }
                },
                {
                  "key": "thread.id",
                  "value": {
                    "intValue": "44"
                  }
                },
                {
                  "key": "thread.name",
                  "value": {
                    "stringValue": "grpc-default-executor-1"
                  }
                }
              ],
              "flags": 1,
              "traceId": "42de1f0dd124e27619a9f3c10bccac1c",
              "spanId": "270984d03e94bb8b"
            }
          ]
        }
      ],
      "schemaUrl": "https://opentelemetry.io/schemas/1.24.0"
    }
  ]
}
```

You can use the following configuration to properly parse and extract the `OTLP` content from these log lines:

```yaml
receivers:
  filelog/otlpjson:
    include: [/path/to/myapp/otlpjson.log]

connectors:
  otlpjson:

service:
  pipelines:
    logs/otlpjson:
      receivers: [filelog/otlpjson]
      processors: []
      exporters: [otlpjson]
    logs:
      receivers: [otlp, otlpjson]
      processors: []
      exporters: [debug]
...
```

## Parse apache logs

You can parse logs of a known technology, like Apache logs, through filelog receiver's operators. Use the [`regex_parser`](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/v0.123.0/pkg/stanza/docs/operators/regex_parser.md) operator to parse the logs that follow the specific pattern:

```yaml
receivers:
  # Receiver to read the Apache logs
  filelog:
    include:
    - /var/log/*apache*.log
    start_at: end
    operators:
    # Operator to parse the Apache logs
    # This operator uses a regex to parse the logs
    - id: apache-logs
      type: regex_parser
      regex: ^(?P<source_ip>\d+\.\d+.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp_log>\d+/\w+/\d+:\d+:\d+:\d+\s+\+\d+)\]\s"(?P<http_method>\w+)\s+(?P<http_path>.*)\s+(?P<http_version>.*)"\s+(?P<http_code>\d+)\s+(?P<http_size>\d+)$
```

## Customize logs parsing on Kubernetes

The OpenTelemetry Collector also supports dynamic logs collection for Kubernetes Pods by defining Pods annotations. For detailed examples refer to [Dynamic workload discovery on Kubernetes now supported with EDOT Collector](https://www.elastic.co/observability-labs/blog/k8s-discovery-with-EDOT-collector) and the
[Collector documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/receivercreator/README.md#supported-logs-annotations).

Make sure that the Collector configuration includes the [`k8s_observer`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.123.0/extension/observer/k8sobserver) and the [`receiver_creator`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.123.0/receiver/receivercreator):

```yaml
receivers:
  receiver_creator/logs:
    watch_observers: [k8s_observer]
    discovery:
      enabled: true
    receivers:

# ...

extensions:
  k8s_observer:

# ...

service:
  extensions: [k8s_observer]
  pipelines:
    logs:
      receivers: [ receiver_creator/logs]
```

In addition, make sure to remove or comment out any static filelog receiver. Restrict the log file pattern to avoid log duplication.

Annotating the pod activates custom log collection targeted only for the specific Pod.

```yaml
# ...
metadata:
  annotations:
    io.opentelemetry.discovery.logs/enabled: "true"
    io.opentelemetry.discovery.logs/config: |
      operators:
      - id: container-parser
        type: container
      # Check if format is json and route properly
      - id: get-format
        routes:
        - expr: body matches "^\\{"
          output: json-parser
        type: router
      - id: json-parser
        type: json_parser
        on_error: send_quiet
        parse_from: body
        parse_to: body
      - id: custom-value
        type: add
        field: attributes.tag
        value: custom-value
spec:
    containers:
    # ...
```

Targeting a single container's scope is also possible by scoping the annotation using containers' names, like `io.opentelemetry.discovery.logs.my-container/enabled: "true"`. Refer to the [Collector's documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/receivercreator/README.md#supported-logs-annotations) for additional information.

### Collect Apache logs using annotations discovery

Use the following example to collect and parse Apache logs by annotating Apache containers:

```yaml
metadata:
  annotations:
    io.opentelemetry.discovery.logs.apache/enabled: "true"
    io.opentelemetry.discovery.logs.apache/config: |
      operators:
        - type: container
          id: container-parser
        - id: apache-logs
          type: regex_parser
          regex: ^(?P<source_ip>\d+\.\d+.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp_log>\d+/\w+/\d+:\d+:\d+:\d+\s+\+\d+)\]\s"(?P<http_method>\w+)\s+(?P<http_path>.*)\s+(?P<http_version>.*)"\s+(?P<http_code>\d+)\s+(?P<http_size>\d+)$
spec:
    containers:
      - name: apache
      # ...
```

## Use processors and OTTL for logs processing

You can use [OpenTelemetry Transform Language (OTTL)](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/pkg/ottl/README.md) functions in the transform processor to parse logs of a specific format or logs that follow a specific pattern. 

### Parse JSON logs using OTTL

Use the following [`transform`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.123.0/processor/transformprocessor)
processor configuration to parse logs in `JSON` format:

```yaml
processors:
  transform:
    error_mode: ignore
    log_statements:
      - context: log
        statements:
          # Parse body as JSON and merge the resulting map with the cache map, ignoring non-json bodies.
          # cache is a field exposed by OTTL that is a temporary storage place for complex operations.
          - merge_maps(cache, ParseJSON(body), "upsert") where IsMatch(body, "^\\{")
          - set(body,cache["log"]) where cache["log"] != nil
```

### Parse Apache logs using OTTL

The following configuration can parse Apache access log using OTTL and the transform processor:

```yaml
exporters:
  debug:
    verbosity: detailed
receivers:
  filelog:
    include:
      - /Users/chrismark/otelcol/log/apache.log


processors:
  transform/apache_logs:
    error_mode: ignore
    log_statements:
      - context: log
        statements:
          - 'merge_maps(attributes, ExtractPatterns(body, "^(?P<source_ip>\\d+\\.\\d+.\\d+\\.\\d+)\\s+-\\s+-\\s+\\[(?P<timestamp_log>\\d+/\\w+/\\d+:\\d+:\\d+:\\d+\\s+\\+\\d+)\\]\\s\"(?P<http_method>\\w+)\\s+(?P<http_path>.*)\\s+(?P<http_version>.*)\"\\s+(?P<http_code>\\d+)\\s+(?P<http_size>\\d+)$"), "upsert")'
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [transform/apache_logs]
      exporters: [debug]


```

A more detailed example about using OTTL and the transform processor can be found at the
[nginx_ingress_controller_otel](https://github.com/elastic/integrations/blob/main/packages/nginx_ingress_controller_otel/docs/README.md)
integration.

## Exclude paths from logs collection [exclude-logs-paths]

To exclude specific paths from logs collection, use the `exclude` field in the `logs` pipeline configuration. Exclude patterns are applied against the paths matched by include patterns. For example:

::::{tab-set}
:::{tab-item} Standalone
```yaml
receivers:
  # Receiver for platform specific log files
  filelog/platformlogs:
    include: [/var/log/*.log]
    retry_on_failure:
      enabled: true
    start_at: end
    storage: file_storage
    exclude:
      # Paths support glob patterns
      - /var/log/ignore_this.log
      - /var/log/another_path/*
```
:::

:::{tab-item} Kubernetes
```yaml
mode: daemonset

presets:
  logsCollection:
    enabled: true
config:
  receivers:
    filelog:
      exclude:
        # Paths support glob patterns
        - /var/log/pods/my-nodejs-app-namespace_my-nodejs-app-pod-name_*/*/*.log
```
:::
::::
