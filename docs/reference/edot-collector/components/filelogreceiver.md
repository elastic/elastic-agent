---
title: File log receiver
description: The File log receiver is an OpenTelemetry Collector component that ingests logs from files.
products:
  - id: elastic-agent
  - id: cloud
  - id: observability
  - id: edot-collector
---

# File log receiver

The File log receiver ingests logs from local files and forwards them for processing and exporting. It is a versatile and widely-used component for collecting logs in file-based formats, such as container logs, system logs, or custom application logs.

The receiver supports multiline parsing, filtering, persistent tracking of file offsets, and routing based on file metadata or log content.


## Example configuration

This example shows how to ingest Kubernetes container logs with routing logic based on log format:

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


## **Key configuration options**

| Option | Description |
|---------|-------------|
| `include` | List of glob patterns for files to include |
| `exclude` | Optional glob patterns for files to exclude |
| `start_at` | `beginning` or `end`. Controls where to start reading |
| `operators` | Parsing and routing logic for logs |
| `storage` | Enables persistent state to avoid duplications on restarts |
| `max_log_size` | Maximum size of individual log entries (in bytes) |

For the full list of options, refer to the[ upstream `filelogreceiver` docs](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md).


## **Best practices**

* Use [persistent storage](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/design.md#storage-extension) to avoid duplicate log entries after restarts.

* Leverage `operators` to normalize log formats (for example parse JSON, regex fields).
* Use the `router` operator when handling multiple formats (for example containerd and CRI-O). 
* Avoid using the `start_at: end` setting in ephemeral containers (risk of missing logs).
* Use `exclude` for rotated or compressed logs you don’t want ingested.


## Limitations

* The `filelogreceiver` does not support dynamic file discovery inside containers.

* High-volume directories (for example `/var/log/containers`) may require tuning `max_concurrent_files`.

* File renaming or rotation may cause skipped or duplicated lines without fingerprinting.


## Resources

* [Upstream component: filelogreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/filelogreceiver/README.md)
* [Configure logs collection in EDOT](https://www.elastic.co/docs/reference/edot-collector/config/configure-logs-collection)
