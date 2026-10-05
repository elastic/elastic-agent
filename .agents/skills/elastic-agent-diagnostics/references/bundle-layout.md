# Diagnostics Bundle Layout

The bundle is a `.zip` produced by `elastic-agent diagnostics`. Files sit at the zip root; all paths below are relative to it. Which files are present varies by agent version and mode — treat a missing file as information (see the end of this page), not as a broken bundle.

## Top-level files

| File | Contents |
|---|---|
| `version.txt` | Agent binary version, as YAML: `version`, `commit`, `build_time`, `snapshot`, `fips` |
| `package.version` | Installed package version (plain string); differs from `version.txt`'s `version` during an upgrade-in-progress |
| `agent-info.yaml` | Agent identity and log levels (`log_level`, `log_level_policy`, `log_level_override`), plus `metadata` (host, build, `upgradeable`, …) |
| `local-config.yaml`, `pre-config.yaml` | The on-disk agent config, and the policy before variable substitution |
| `environment.yaml` | The agent process's environment variables (sensitive values redacted) |
| `state.yaml` | **Primary diagnostic file.** Current agent state snapshot: top-level status, per-component states, per-unit states and payloads, OTel collector status. See below. |
| `components-expected.yaml` | The component model the coordinator has compiled from the latest policy — what it *wants* to run. |
| `components-actual.yaml` | The component model the coordinator has actually applied — what is *running*. Usually byte-identical to `components-expected.yaml` once converged. A diff between them signals an in-flight or stuck reconfiguration. |
| `computed-config.yaml` | The fully-resolved agent policy after variable substitution, including all output and input configs. Sensitive fields (passwords, API keys, certs) are redacted to `<REDACTED>`. |
| `otel.yaml` | The OTel config delivered via policy / user override. "no active OTel configuration" when none has been applied. |
| `otel-merged.yaml` | The merged running OTel collector config (agent-managed components + user-provided otel.yaml). This is what the collector is *actually running*. Use this to check which receivers/exporters/pipelines are active. |
| `variables.yaml` | Fleet-provided dynamic variable values (host metadata, cloud provider info, etc.) |
| `*.pprof.gz` | Agent process profiles at the root: `goroutine`, `heap`, `allocs`, `block`, `mutex`, `threadcreate`; `cpu.pprof` only with `--cpu-profile` |

## `state.yaml` structure

The most important file in the bundle. Key fields:

```yaml
state: <int>          # top-level agent state (see state-enums.md)
message: <string>     # human-readable state message
fleet_state: <int>    # Fleet connection state
fleet_message: <string>
log_level: <string>   # e.g. "info"
collector:            # present when the OTel collector runtime is in use
  status: <int>       # OTel collector health state (see state-enums.md)
  error: <string>     # only when set
  timestamp: <RFC3339>
  components: {}      # only when the collector reports per-pipeline/per-component status: same shape, nested
upgrade_details: {}   # only while an upgrade is in progress or recently finished
components:
  - id: <string>      # e.g. "filestream-monitoring", "packet-default"
    state:
      state: <int>    # component state (see state-enums.md)
      message: <string>
      pid: <int>      # only non-zero for Endpoint (the agent doesn't know beat PIDs); 0 otherwise
    units:
      <type>-<unit-id>:    # key is "input-<id>" or "output-<id>"
        state: <int>
        message: <string>
        payload: {}   # unit-specific runtime state (streams, etc.)
```

`components-expected.yaml` and `components-actual.yaml` share the same schema as the `components:` list but carry the full compiled spec (binary path, spec, units with config).

## `logs/` directory

```
logs/
  elastic-agent-<version>-<hash>/
    elastic-agent-<YYYYMMDD>[-N].ndjson            # agent (supervisor) log, plus captured output of process-mode components
    elastic-otel-collector-<YYYYMMDD>[-N].ndjson   # EDOT collector log, when the collector runs as its own process
    elastic-agent-watcher-<YYYYMMDD>[-N].ndjson    # upgrade watcher log
    elastic-agent-metrics.ndjson                   # periodic agent metrics
    components/                                    # per-component log files, when present
  services/
    endpoint-*.log                                 # Elastic Endpoint's own log (ECS JSON, nested fields) — when Endpoint is installed
```

A new file starts on rotation or process restart: the un-suffixed file is the **oldest** of the day, then `-1`, `-2`, … — the highest `N` is the newest. Concatenate and sort by `@timestamp` rather than relying on names.

**Key fields per log line:**

| Field | Meaning |
|---|---|
| `@timestamp` | RFC3339 UTC timestamp |
| `log.level` | `debug`, `info`, `warn`, `error` |
| `message` | Human-readable message |
| `log.source` | `"elastic-agent"` for L1 supervisor lines; the component id (e.g. `"synthetics/http-default"`) for captured output of a process-mode component; absent for OTel collector lines |
| `log.logger` | Package-level logger name (e.g. `"coordinator"`, `"component.runtime.supervisor"`, `"component.runtime.endpoint.service_runtime"`). Supervisor-bridge lines have names starting with `"component.runtime."`. |
| `component.id` | Component ID the line relates to. Nested (`.component.id`) on supervisor lines, a flat key (`.["component.id"]`) on captured process-mode output — query both |
| `component.state` | State string at the time of log (when applicable) |
| `service.name` | the beat (`"filebeat"`, `"metricbeat"`, `"heartbeat"`, …) for beat lines (L4); `"elastic-otel-collector"` for collector core and pipeline-component lines |
| `otelcol.component.id` | OTel component ID for pipeline component lines (L3), e.g. `"filebeatreceiver/_agent-component/filestream-monitoring"` |
| `otelcol.component.kind` | `"receiver"`, `"processor"`, `"exporter"`, `"extension"` (L3) |

## `components/` directory

Per-component subdirectories, named by component id with `/` replaced by `-` (e.g. `http/metrics-monitoring` → `http-metrics-monitoring`), then per unit:

```
components/
  filestream-monitoring/
    filestream-monitoring-agent/     # unit id
      beat_metrics.json              # libbeat pipeline and output statistics
      input_metrics.json             # per-input metrics
      registry.tar.gz                # filebeat registry (omitted if > 20 MB); extracts to registry/filebeat/{log,meta}.json
  http-metrics-monitoring/
    ...
```

When Elastic Endpoint is installed, `components/endpoint/` holds Endpoint's own diagnostics instead: `policy_response.json`, `elastic-endpoint.yaml`, `metrics.json`, `version.txt`, `system_info.txt` (or `error.txt` if Endpoint didn't answer within 20 s). See [runtimes.md](runtimes.md).

`beat_metrics.json` top-level keys: `libbeat.pipeline.events`, `libbeat.output`, `libbeat.config`, `system.cpu`, `system.load`.

## `edot/` directory (EDOT collector, OTel mode only)

Present when the agent is running in OTel runtime mode.

```
edot/
  otel-merged-actual.yaml   # The config the EDOT collector process is actually running (may differ from top-level otel-merged.yaml during a transition)
  environment.yaml          # the collector process's environment
  goroutine.profile.gz      # pprof goroutine profile for the collector process
  heap.profile.gz           # pprof heap profile
  allocs.profile.gz
  block.profile.gz
  mutex.profile.gz
  threadcreate.profile.gz
```

## Profiles

Agent-process profiles are at the bundle root (`goroutine.pprof.gz`, `heap.pprof.gz`, …); EDOT collector profiles are in `edot/*.profile.gz`. All are readable directly by `go tool pprof`; `.gz` files are decompressed automatically.

## Notable absences and what they mean

| Missing file / dir | Likely reason |
|---|---|
| `edot/` absent | Agent is not in OTel runtime mode; components run as subprocesses |
| `otel.yaml` says "no active OTel configuration" | No OTel config has been pushed via policy; expected in non-OTel setups |
| `components/` missing a component | Component was not running at the time of bundle collection |
| `registry.tar.gz` absent | Registry > 20 MB limit; agent logged a skip warning |
| `cpu.pprof` absent | Bundle was collected without `--cpu-profile`; normal for most production bundles |
| `elastic-agent-watcher-*.ndjson` absent | No upgrade was in progress at bundle collection time |
