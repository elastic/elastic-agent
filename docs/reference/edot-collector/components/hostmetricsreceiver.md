---
navigation_title: Host metrics receiver
description: The host metrics receiver is an OpenTelemetry Collector component that collects system-level metrics from the host machine.
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

# Host metrics receiver

The host metrics receiver collects system-level metrics from the host machine, including CPU usage, memory, disk I/O, network traffic, filesystem statistics, and process information. It provides essential infrastructure monitoring data that powers {{product.observability}}'s [Infrastructure dashboards](docs-content://reference/observability/observability-host-metrics.md).

The receiver uses a set of specialized scrapers to gather metrics from different subsystems, making it flexible enough to collect only the metrics you need.

## Default usage in EDOT

The `hostmetricsreceiver` is included by default in the EDOT Collector for both standalone and Kubernetes deployments.

### Standalone agent mode

In standalone deployments, the host metrics receiver is part of the default [host metrics collection pipeline](../config/default-config-standalone.md#host-metrics-collection-pipeline). It collects system metrics at 60-second intervals and can be configured to export either:

- Directly to {{es}} using the `elasticsearch` exporter (with optional ECS translation through the `elasticinframetrics` processor).
- To the [{{motlp}}](opentelemetry://reference/motlp.md) using the `otlp` exporter.

### Kubernetes deployment

In Kubernetes, the host metrics receiver runs as part of the [DaemonSet collectors pipeline](../config/default-config-k8s.md#daemonset-collectors-pipeline) on every node to collect node-level host metrics at 60-second intervals. The receiver uses `root_path: /hostfs` (a mounted Kubernetes volume) to access the host's filesystem from within the container.

For more details about the Kubernetes configuration, refer to [Default configuration (Kubernetes)](../config/default-config-k8s.md).

### Common configuration

Across all deployment modes, the default configuration collects CPU, memory, disk, filesystem, network, and load metrics. Process-level metrics are turned off by default to avoid generating excessive timeseries data.

For more details on configuring metrics collection, refer to [Configure metrics collection guide](../config/configure-metrics-collection.md#host-metrics).

## Example configuration

The following example shows a typical host metrics receiver configuration with commonly used scrapers:

```yaml
receivers:
  hostmetrics:
    collection_interval: 60s
    root_path: /hostfs  # Mounted host root filesystem
    scrapers:
      cpu:
        metrics:
          system.cpu.utilization:
            enabled: true
          system.cpu.logical.count:
            enabled: true
      memory:
        metrics:
          system.memory.utilization:
            enabled: true
      disk: {}
      filesystem:
        exclude_mount_points:
          mount_points:
            - /dev/*
            - /proc/*
            - /sys/*
            - /var/lib/docker/*
            - /var/lib/kubelet/*
          match_type: regexp
        exclude_fs_types:
          fs_types:
            - autofs
            - binfmt_misc
            - bpf
            - cgroup2
            - configfs
            - debugfs
            - devpts
            - devtmpfs
            - overlay
            - proc
            - sysfs
          match_type: strict
      load: {}
      network: {}
      processes: {}
```

## Available scrapers

The host metrics receiver supports multiple scrapers, each focused on a different subsystem. You can enable only the scrapers you need:

| Scraper | Description | Key Metrics |
|---------|-------------|-------------|
| `cpu` | CPU usage and time | `system.cpu.time`, `system.cpu.utilization`, `system.cpu.logical.count` |
| `memory` | Memory usage by state (used, free, cached, buffered) | `system.memory.usage`, `system.memory.utilization` |
| `disk` | Disk I/O operations and throughput | `system.disk.io`, `system.disk.operations`, `system.disk.io_time` |
| `filesystem` | Filesystem usage and inodes | `system.filesystem.usage`, `system.filesystem.utilization` |
| `network` | Network traffic and errors | `system.network.io`, `system.network.errors`, `system.network.connections` |
| `load` | System load average | `system.cpu.load_average.1m`, `system.cpu.load_average.5m`, `system.cpu.load_average.15m` |
| `processes` | Process count by state | `system.processes.count`, `system.processes.created` |
| `process` | Per-process metrics (CPU, memory, I/O) | `process.cpu.time`, `process.memory.usage`, `process.disk.io` |
| `paging` | Paging and swap operations | `system.paging.operations`, `system.paging.usage` |

## Key configuration options

These are the most important settings when configuring the host metrics receiver:

| Option | Description |
|--------|-------------|
| `collection_interval` | How often to scrape metrics (for example `60s`, `30s`). Defaults to `1m`. |
| `root_path` | Root directory to use when running in a container. Set to `/hostfs` when mounting the host's root filesystem. |
| `scrapers` | Map of scraper names to their configurations. Each scraper can be customized individually. |
| `scrapers.<name>.metrics` | Control which specific metrics are enabled for a given scraper. |

For the complete list of configuration options and scraper-specific settings, refer to the [contrib `hostmetricsreceiver` documentation](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md).

## Best practices

Follow these recommendations to get the most value from the host metrics receiver:

* **Use the `root_path` setting when running in containers**: When the collector runs inside a container, it needs access to the host's filesystem to collect accurate metrics. Mount the host's root directory (typically at `/`) and set `root_path: /hostfs` in your configuration. This ensures the receiver reads from the host's `/proc`, `/sys`, and other system directories rather than the container's isolated filesystem.

* **Filter out non-data filesystems and mount points**: To avoid collecting metrics from temporary, virtual, or container-specific filesystems, use the `exclude_mount_points` and `exclude_fs_types` options in the filesystem scraper. The default EDOT configuration already excludes common noise sources like `/dev/*`, `/proc/*`, `/sys/*`, overlay filesystems, and various pseudo-filesystems.

* **Start with essential scrapers, then expand as needed**: Begin with the core scrapers (`cpu`, `memory`, `disk`, `filesystem`, `network`, `load`) that provide the foundation for infrastructure monitoring. These align with Elastic's Infrastructure dashboards and provide the most immediate value. Add additional scrapers like `paging` or `processes` based on your specific monitoring requirements.

* **Be cautious when enabling the `process` scraper**: The `process` scraper collects per-process metrics, which can generate thousands of timeseries on systems with many running processes. This significantly increases storage requirements and can impact collector performance. Only enable it when you have a specific need for process-level visibility and have tested the volume impact in your environment.

* **Align collection intervals with your monitoring needs**: The default 60-second interval balances freshness with overhead. For high-resolution monitoring, you can decrease to 30s or even 10s, but be aware this increases ingestion volume and associated costs. For less critical systems, increasing to 120s or 300s can reduce load.

* **Enable specific metrics within scrapers for optimization**: Most scrapers expose a `metrics:` configuration block where you can enable or disable individual metrics. Use this to reduce cardinality and ingestion volume by collecting only the metrics you actually use in your dashboards and alerts.


## Limitations

Be aware of these constraints and behaviors when using the host metrics receiver:

* **Process metrics are turned off by default**: The `process` scraper generates significant metric volume and is commented out in EDOT default configuration. Turning it on can substantially increase storage requirements and costs. Refer to the contrib [issue #39423](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/39423) for ongoing discussion about optimizing process metrics collection.

* **Container deployment requires privileged access**: To collect host metrics from inside a container (Kubernetes DaemonSet), the collector must run with elevated privileges (`runAsUser: 0`) and have the host's `/proc` and `/sys` filesystems mounted. Refer to the [collecting host metrics from inside a container](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/hostmetricsreceiver#collecting-host-metrics-from-inside-a-container-linux-only) guide for details.

* **Platform-specific metric availability**: Some metrics are only available on certain operating systems. For example, load average metrics work on Linux and macOS but not on Windows. The receiver logs warnings for unsupported metrics rather than failing.

* **Filesystem scraper requires careful filtering**: Without proper exclusions, the filesystem scraper can collect metrics from hundreds of temporary, virtual, or container-specific mount points, generating unnecessary data. Always configure `exclude_mount_points` and `exclude_fs_types` appropriately.

* **Metric format differs from {{agent}} system integration**: Host metrics collected through OpenTelemetry use different field names and structure compared to {{agent}}'s traditional system integration. The [`elasticinframetrics` processor](https://github.com/elastic/opentelemetry-collector-components/tree/main/processor/elasticinframetricsprocessor) is required to translate OTel metrics into ECS-compatible format for use with existing Infrastructure dashboards.

## Resources

* [Contrib component: hostmetricsreceiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md)
* [Configure metrics collection in EDOT](../config/configure-metrics-collection.md)
* [{{product.observability}} host metrics reference](https://www.elastic.co/docs/reference/observability/observability-host-metrics)

