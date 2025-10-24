---
navigation_title: File log receiver
description: The file log receiver is an OpenTelemetry Collector component that ingests logs from files.
applies_to:
  stack:
  serverless:
    observability:
  product:
    edot_collector:
products:
  - id: elastic-agent
  - id: observability
  - id: edot-collector
---

# File log receiver

The file log receiver ingests logs from local files and forwards them for processing and exporting. It is a versatile and widely-used component for collecting logs in file-based formats, such as container logs, system logs, or custom application logs.

The receiver supports multiline parsing, filtering, persistent tracking of file offsets, and routing based on file metadata or log content.


## Default usage in EDOT

The `filelogreceiver` is included by default in the EDOT Collector's Kubernetes Helm chart. It is preconfigured to collect logs from pod log files such as `/var/log/pods/*/*/*.log`, and uses the `file_storage` extension to track read positions and avoid duplicate ingestion after restarts.

To view or customize the default configuration, refer to:

- [`logs collection config`](https://github.com/elastic/elastic-agent/blob/v9.1.4/deploy/helm/edot-collector/kube-stack/values.yaml#L179-L181)
- [`filelogreceiver options`](https://github.com/elastic/elastic-agent/blob/v9.1.4/deploy/helm/edot-collector/kube-stack/values.yaml#L322-L335)


## Example configuration

The following example shows how to ingest Kubernetes container logs with routing logic based on log format:

```yaml
receivers:
  filelog:
    include:
      - /var/log/pods/*/*/*.log
    exclude:
      - /var/log/pods/*/*/*.gz
    start_at: beginning
    include_file_name: true
    include_file_path: true
    fingerprint_size: 100
    max_log_size: 102_400
    storage: file_storage
    operators:
      - type: router
        routes:
          - output: parser_containerd
            expr: 'body matches "^\\d{4}-\\d{2}-\\d{2}T"'
          - output: parser_crio
            expr: 'body matches "^[A-Z][a-z]{2} [0-9]{1,2} "'

      - id: parser_containerd
        type: json_parser
        timestamp:
          parse_from: attributes.time
          layout_type: gotime
          layout: 2006-01-02T15:04:05.000000000Z07:00

      - id: parser_crio
        type: regex_parser
        regex: '^(?P<time>[^ ]+ [^ ]+) (?P<stream>stdout|stderr) (?P<logtag>[^ ]*) (?P<body>.*)'
        timestamp:
          parse_from: attributes.time
          layout: '%b %d %H:%M:%S'
```


## Key configuration options

The following are some of the most commonly used settings when working with the file log receiver. These options help control what files are read, how logs are parsed, and how file positions are tracked between restarts:

| Option | Description |
|---------|-------------|
| `include` | List of glob patterns for files to include. |
| `exclude` | Optional glob patterns for files to exclude (for example rotated or compressed files). |
| `start_at` | `beginning` or `end`. Controls where to start reading files when no checkpoint exists. |
| `operators` | Parsing and routing logic for logs. |
| `storage` | Enables persistent tracking of file positions using a storage extension. |
| `max_log_size` | Maximum size of individual log entries (in bytes). |
| `fingerprint_size`| Size (in bytes) used to identify and deduplicate files. |

For the full list of options, refer to the [upstream `filelogreceiver` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md).


## Best practices

These tips can help you get the most out of the file log receiver:

### Use [persistent storage](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/design.md#storage-extension) to avoid duplicates
  Without persistent storage, the receiver will not retain file read positions across restarts. This can result in either duplicate ingestion (if `start_at` is set to `beginning`) or lost logs (if set to `end`). Use the `storage:` setting and configure a persistent volume when running in Kubernetes.

### Exclude rotated or compressed log files unless needed
  The default configuration excludes rotated files, which helps prevent duplicate ingestion. If you need to include rotated logs, update the `include:` and `exclude:` patterns accordingly.

### Enable multiline log parsing for stack traces and similar patterns
  Multiline log support is not enabled by default. To handle multi-line messages such as stack traces, define a `regex_parser`, `combine_logs`, or `multiline` operator in your Helm chart configuration.

### Route different log formats using conditional parsing 
  If your environment produces logs in multiple formats (for example containerd and CRI-O), use the `router` operator to apply appropriate parsers based on the log structure.

### Avoid using `start_at: beginning` without storage
  Using `start_at: beginning` without a storage extension will re-read all files from the start after each restart, which might lead to duplicate log entries.


## Limitations

Like any component, file log receiver has some trade-offs and behaviors to be aware of, especially in Kubernetes environments:

* Persistent log tracking requires explicit `storage:` configuration and persistent volume support in Kubernetes.

* Multiline logs are not parsed by default. You must customize the configuration to parse them.

* Incorrect include/exclude globs can result in missing rotated logs or unintended ingestion.

* High-volume directories might require tuning of `max_concurrent_files`.


## Resources

* [Upstream component: filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md)
* [Configure logs collection in EDOT](../config/configure-logs-collection.md)
* [Helm chart default values](https://github.com/elastic/elastic-agent/blob/v9.1.4/deploy/helm/edot-collector/kube-stack/values.yaml)