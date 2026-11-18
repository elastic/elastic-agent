# Diagnostics bundle

`elastic-agent diagnostics` writes a `.zip` bundle with the agent's state, configuration, logs, component diagnostics
and Go pprof profiles. This page describes what is in it. Passwords, tokens, API keys and certificates are redacted
(see [PII_HANDLING.md](./PII_HANDLING.md)). The bundle is a snapshot: `state.yaml` and the configs reflect the moment
the command ran, only the logs cover history. All timestamps are UTC.

Which files are present depends on the agent version, mode and runtimes in use, so a missing file is information
rather than a broken bundle (see [Missing files](#missing-files)).

## Top-level files

| File | Contents |
|---|---|
| `version.txt` | Agent binary version, as YAML: `version`, `commit`, `build_time`, `snapshot`, `fips` |
| `package.version` | Installed package version. Differs from `version.txt` while an upgrade is in progress |
| `agent-info.yaml` | Agent identity, log levels and metadata (host, build, `upgradeable`, ...) |
| `local-config.yaml`, `pre-config.yaml` | The on-disk agent config, and the policy before variable substitution |
| `environment.yaml` | The agent process's environment variables |
| `state.yaml` | The agent state snapshot, see below |
| `components-expected.yaml` | The component model compiled from the latest policy: what the agent wants to run |
| `components-actual.yaml` | The component model the coordinator has applied: what is running. Usually identical to `components-expected.yaml` once converged, a difference means a reconfiguration is in flight or stuck |
| `computed-config.yaml` | The fully resolved policy after variable substitution |
| `otel.yaml` | The OTel config delivered by policy or user override, or "no active OTel configuration" |
| `otel-merged.yaml` | The merged OTel collector config (agent-managed components plus `otel.yaml`): which receivers, exporters and pipelines the collector is running |
| `variables.yaml` | Values of the dynamic variables provided to the policy (host metadata, cloud provider info, ...) |
| `*.pprof.gz` | Agent process profiles: `goroutine`, `heap`, `allocs`, `block`, `mutex`, `threadcreate`, and `cpu.pprof` only when collected with `--cpu-profile` |

## `state.yaml`

```yaml
state: <int>          # agent state, see "State values"
message: <string>
fleet_state: <int>    # Fleet connection state, same enum
fleet_message: <string>
log_level: <string>
collector:            # present when the OTel runtime is in use
  status: <int>       # OTel collector status, see "State values"
  error: <string>     # only when set
  timestamp: <RFC3339>
  components: {}      # per-pipeline and per-component status, same shape, nested
upgrade_details: {}   # only while an upgrade is in progress or recently finished
components:
  - id: <string>
    state:
      state: <int>
      message: <string>
      version_info:
        name: <string> # identifies the runtime, see below
      pid: <int>      # only non-zero for service components (Endpoint)
    units:
      <input|output>-<unit id>:
        state: <int>
        message: <string>
        payload: {}   # unit specific runtime state
```

The runtime of a component can be told from `state.version_info.name`: `beats-receiver` for the OTel runtime,
`beat-v2-client` for beats in the process runtime and `Endpoint` for the service runtime. See
[architecture.md](./architecture.md#runtime-manager) for the runtimes. `state.yaml` shows the runtime at the time of
the snapshot, if the component switched runtimes the logs contain both.

### State values

`state`, `fleet_state` and the component and unit states use the `cproto.State` enum
(`pkg/control/v2/cproto/control_v2.pb.go`):

| Int | Name |
|---|---|
| 0 | STARTING |
| 1 | CONFIGURING |
| 2 | HEALTHY |
| 3 | DEGRADED |
| 4 | FAILED |
| 5 | STOPPING |
| 6 | STOPPED |
| 7 | UPGRADING |
| 8 | ROLLBACK |

`fleet_state` other than 2 means Fleet Server connectivity is broken. After an unenroll the Fleet gateway is stopped
and `fleet_state` keeps its last value. A component that stays in STOPPING did not acknowledge a stop request.

`collector.status` is the OTel `componentstatus.Status` of the whole collector: 0 None, 1 Starting, 2 OK,
3 RecoverableError, 4 PermanentError, 5 FatalError, 6 Stopping, 7 Stopped. It only covers the components the collector
is currently running: a collector without a receiver that should be running still reports OK. Compare
`components-expected.yaml` with `otel-merged.yaml` to check that all expected receivers are present.

## Logs

Logs are described in [elastic-agent-logging.md](./elastic-agent-logging.md#collecting-logs-for-diagnostics). They are
collected under `logs/`:

```
logs/
  elastic-agent-<version>-<hash>/
    elastic-agent-<YYYYMMDD>[-N].ndjson            # agent log, plus captured output of process-mode components
    elastic-otel-collector-<YYYYMMDD>[-N].ndjson   # EDOT collector log
    elastic-agent-watcher-<YYYYMMDD>[-N].ndjson    # upgrade watcher log
    elastic-agent-metrics.ndjson                   # periodic agent metrics
    components/                                    # per-component log files
    events/                                        # output event log: why the output rejected or dropped events
  services/
    endpoint-*.log                                 # Elastic Endpoint's own log (ECS JSON with nested fields)
```

A new file is started on rotation or process restart. The file without a suffix is the oldest of the day, and the
highest `N` is the newest.

Notable fields of the NDJSON log lines:

| Field | Meaning |
|---|---|
| `@timestamp`, `log.level`, `message` | Time, level (`debug`, `info`, `warn`, `error`) and message |
| `log.source` | `elastic-agent` for agent lines, the component id for captured output of a process-mode component, absent for collector lines |
| `log.logger` | The logger name, for example `coordinator` or `component.runtime.endpoint.service_runtime` |
| `component.id` | The component the line relates to. Nested on agent lines, a flat key on captured process-mode output |
| `service.name` | The Beat (`filebeat`, `metricbeat`, ...) for Beat lines, `elastic-otel-collector` for collector lines |
| `otelcol.component.id`, `otelcol.component.kind` | The OTel component (for example `filebeatreceiver/_agent-component/<id>`) and its kind, for pipeline component lines |

The elastic-agent logs the output of Endpoint's installer at `error` level regardless of its content, which inflates
error counts for agents with Endpoint.

## `components/`

Per-component directories, named after the component id with `/` replaced by `-`, with a directory per unit holding
`beat_metrics.json` (libbeat pipeline and output statistics), `input_metrics.json`, and for Filebeat
`registry.tar.gz` (omitted when the registry is large). For Endpoint, `components/endpoint/` holds Endpoint's own diagnostics:
`policy_response.json`, `elastic-endpoint.yaml`, `metrics.json`, `version.txt` and `system_info.txt`, or `error.txt`
if Endpoint did not answer within 20 seconds.

## `edot/`

Present when the OTel runtime is in use: `otel-merged-actual.yaml` (the config the collector process is actually
running, which can differ from `otel-merged.yaml` during a transition), the collector's `environment.yaml` and its
pprof profiles (`*.profile.gz`).

## Missing files

| Missing | Likely reason |
|---|---|
| `edot/` | No component runs in the OTel runtime |
| `components/` entry for a component | The component was not running when the bundle was collected |
| `registry.tar.gz` | The registry was too large to include |
| `cpu.pprof` | The bundle was collected without `--cpu-profile` |
| `elastic-agent-watcher-*.ndjson` | No upgrade has happened recently |
