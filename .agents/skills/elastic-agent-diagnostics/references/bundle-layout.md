# Diagnostics Bundle Layout

The bundle is a `.zip` produced by `elastic-agent diagnostics`. All paths below are relative to the bundle root (the top-level directory inside the zip).

## Top-level files

| File | Contents |
|---|---|
| `version.txt` | Agent binary version string (e.g. `9.5.0-SNAPSHOT`) |
| `package.version` | Installed package version; differs from `version.txt` during an upgrade-in-progress |
| `state.yaml` | **Primary diagnostic file.** Current agent state snapshot: top-level status, per-component states, per-unit states and payloads, OTel collector status. See below. |
| `components-expected.yaml` | The component model the coordinator has compiled from the latest policy — what it *wants* to run. |
| `components-actual.yaml` | The component model the coordinator has actually applied — what is *running*. Usually byte-identical to `components-expected.yaml` once converged. A diff between them signals an in-flight or stuck reconfiguration. |
| `computed-config.yaml` | The fully-resolved agent policy after variable substitution, including all output and input configs. Sensitive fields (passwords, API keys, certs) are redacted to `<REDACTED>`. |
| `otel.yaml` | The OTel config delivered via policy / user override. "no active OTel configuration" when none has been applied. |
| `otel-merged.yaml` | The merged running OTel collector config (agent-managed components + user-provided otel.yaml). This is what the collector is *actually running*. Use this to check which receivers/exporters/pipelines are active. |
| `variables.yaml` | Fleet-provided dynamic variable values (host metadata, cloud provider info, etc.) |
| `fleet-policy.yaml` | The raw Fleet policy as received from Fleet Server before compilation. |
| `acl.txt` | (Linux) File ACL for the agent data directory. |

## `state.yaml` structure

The most important file in the bundle. Key fields:

```yaml
state: <int>          # top-level agent state (see state-enums.md)
message: <string>     # human-readable state message
fleet_state: <int>    # Fleet connection state
fleet_message: <string>
log_level: <string>   # e.g. "info"
info:
  id: <uuid>          # agent ID
  version: <string>
  snapshot: <bool>
collector:
  status: <int>       # OTel collector health state (see state-enums.md)
  timestamp: <RFC3339>
components:
  - id: <string>      # e.g. "filestream-monitoring", "packet-default"
    state:
      state: <int>    # component state (see state-enums.md)
      message: <string>
      pid: <int>      # OS PID when running as subprocess; absent for OTel-hosted components
    units:
      <unit-id>:
        state: <int>
        message: <string>
        payload: {}   # unit-specific runtime state (streams, etc.)
```

`components-expected.yaml` and `components-actual.yaml` share the same schema as the `components:` list but carry the full compiled spec (binary path, spec, units with config).

## `logs/` directory

```
logs/
  elastic-agent-<version>-<build>/
    elastic-agent-<YYYYMMDD>-<N>.ndjson   # main agent + OTel collector log (NDJSON, one JSON object per line)
    elastic-agent-watcher-<YYYYMMDD>-<N>.ndjson  # upgrade watcher process log (only during upgrades)
```

Each `.ndjson` file uses log rotation: `N=1` is the most recent. Prior days may have multiple numbered files.

**Key fields per log line:**

| Field | Meaning |
|---|---|
| `@timestamp` | RFC3339 UTC timestamp |
| `log.level` | `debug`, `info`, `warn`, `error` |
| `message` | Human-readable message |
| `log.source` | `"elastic-agent"` for L1 supervisor lines; absent for OTel collector lines |
| `log.logger` | Package-level logger name (e.g. `"coordinator"`, `"component.runtime.supervisor"`, `"component.runtime.endpoint.service_runtime"`). Supervisor-bridge lines have names starting with `"component.runtime."`. |
| `component.id` | Component ID the line relates to (when applicable) |
| `component.state` | State string at the time of log (when applicable) |
| `service.name` | `"filebeat"` or `"metricbeat"` for embedded beat lines (L4) |
| `otelcol.component.id` | OTel component ID for pipeline component lines (L3), e.g. `"filebeatreceiver/_agent-component/filestream-monitoring"` |
| `otelcol.component.kind` | `"receiver"`, `"processor"`, `"exporter"`, `"extension"` (L3) |

## `components/` directory

Per-component subdirectories, keyed by component ID:

```
components/
  filestream-monitoring/
    beat_metrics.json     # libbeat pipeline and output statistics
    <unit-id>/
      input_metrics.json  # per-input metrics
      registry.tar.gz     # filebeat registry (omitted if > 20 MB)
  endpoint/
    ...
```

`beat_metrics.json` top-level keys: `libbeat.pipeline.events`, `libbeat.output`, `libbeat.config`, `system.cpu`, `system.load`.

## `edot/` directory (EDOT collector, OTel mode only)

Present when the agent is running in OTel runtime mode.

```
edot/
  otel-merged-actual.yaml   # The config the EDOT collector process is actually running (may differ from top-level otel-merged.yaml during a transition)
  goroutine.profile.gz      # pprof goroutine profile for the collector process
  heap.profile.gz           # pprof heap profile
  allocs.profile.gz
  block.profile.gz
  mutex.profile.gz
  threadcreate.profile.gz
```

## `pprof/` directory (agent process profiles)

```
pprof/
  goroutine.pprof.gz
  heap.pprof.gz
  allocs.pprof.gz
  block.pprof.gz
  mutex.pprof.gz
  threadcreate.pprof.gz
  cpu.pprof            # only present when --cpu-profile flag was used
```

All files are readable directly by `go tool pprof`. `.gz` files are decompressed automatically.

## Notable absences and what they mean

| Missing file / dir | Likely reason |
|---|---|
| `edot/` absent | Agent is not in OTel runtime mode; components run as subprocesses |
| `otel.yaml` says "no active OTel configuration" | No OTel config has been pushed via policy; expected in non-OTel setups |
| `components/` missing a component | Component was not running at the time of bundle collection |
| `registry.tar.gz` absent | Registry > 20 MB limit; agent logged a skip warning |
| `cpu.pprof` absent | Bundle was collected without `--cpu-profile`; normal for most production bundles |
| `elastic-agent-watcher-*.ndjson` absent | No upgrade was in progress at bundle collection time |
