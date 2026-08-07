Process metrics are turned off by default to avoid generating a large volume of timeseries data. To turn on process metrics, uncomment or add the following section inside the `hostmetrics` receiver configuration:

```yaml
  process:
     mute_process_exe_error: true
     mute_process_io_error: true
     mute_process_user_error: true
     metrics:
        process.threads:
        enabled: true
        process.open_file_descriptors:
        enabled: true
        process.memory.utilization:
        enabled: true
        process.disk.operations:
        enabled: true
```