# State Enumerations

Decoded reference for the integer state values that appear throughout `state.yaml` and the agent logs. Use this file when reading raw YAML/JSON — `state.yaml` stores these as integers.

## Agent top-level state (`state.yaml: state`)

Maps to `cproto.State` (`pkg/control/v2/cproto/control_v2.pb.go`).

| Int | Name | Meaning |
|-----|------|---------|
| 0 | STARTING | Agent process is starting up; subsystems not yet ready |
| 1 | CONFIGURING | Agent has started but is still applying initial configuration |
| 2 | HEALTHY | All components healthy; agent operating normally |
| 3 | DEGRADED | Agent is running but at least one component is degraded |
| 4 | FAILED | Agent has encountered a fatal condition |
| 5 | STOPPING | Agent is shutting down |
| 6 | STOPPED | Agent has stopped cleanly |
| 7 | UPGRADING | An upgrade is in progress |
| 8 | ROLLBACK | An upgrade is being rolled back |

The `fleet_state` field uses the same enum. When `fleet_state != 2` (HEALTHY), Fleet Server connectivity is broken. The converse doesn't hold: after an unenroll the Fleet gateway is stopped and `fleet_state` / `fleet_message` stay frozen at their last values (often `2` / `Connected`).

## Component state (`state.yaml: components[].state.state`)

Same `cproto.State` enum as above. The component-level state reflects what the supervisor observes.

| Int | Name | Typical cause |
|-----|------|---------------|
| 0 | STARTING | Component process/receiver is starting |
| 1 | CONFIGURING | Component received a config update and is applying it |
| 2 | HEALTHY | Component running normally — this is the steady state |
| 3 | DEGRADED | Component running but reporting a problem in its message |
| 4 | FAILED | Component exited unexpectedly or reported a fatal error |
| 5 | STOPPING | Supervisor asked component to stop; waiting for it to exit |
| 6 | STOPPED | Component exited cleanly |

A component stuck at **5 (STOPPING)** is a common failure mode — the supervisor told it to stop but it never acknowledged. This is a strong signal to look at cross-layer discrepancies between L1 and L2/L3.

## Unit state (`state.yaml: components[].state.units[].state`)

Same `cproto.State` enum. Units are the individual input/output configurations within a component (one unit per stream, one unit for the output).

In `state.yaml` the unit's type is part of its key: `input-<unit id>` is a data source (log file, metricset, packet capture, …) and `output-<unit id>` is the output configuration (elasticsearch, logstash, kafka). In `components-*.yaml` the type is a `UnitType` integer: `0` = INPUT, `1` = OUTPUT.

## OTel collector status (`state.yaml: collector.status`)

Serialized from the OTel `componentstatus.Status` of the collector's aggregate status (`coordinator.go`, the `state.yaml` hook). `collector.status` is the aggregate for the whole collector; when the collector reports per-pipeline and per-component status, `collector.components` holds the same structure (`status`, `error`, `timestamp`, nested `components`) for each — look there to see which receiver or exporter is unhealthy. The key is omitted when there is nothing to report.

| Int | Name | Meaning |
|-----|------|---------|
| 0 | StatusNone | Collector not yet initialised or status not yet reported |
| 1 | StatusStarting | Collector process is starting; pipeline not yet ready |
| 2 | StatusOK | Collector and all its pipeline components are healthy |
| 3 | StatusRecoverableError | At least one pipeline component has a recoverable error; collector is still running |
| 4 | StatusPermanentError | At least one pipeline component has a permanent error |
| 5 | StatusFatalError | The collector process itself has encountered a fatal error |
| 6 | StatusStopping | Collector is shutting down its pipeline |
| 7 | StatusStopped | Collector has stopped cleanly |

**Important caveat:** `collector.status: 2` (StatusOK) means the collector process and its *currently-running* pipeline components are healthy. It does **not** mean all expected components (from `components-expected.yaml`) are present. A collector running only monitoring receivers (filebeatreceiver for logs, metricbeatreceiver for metrics) while a data receiver (e.g. packetbeatreceiver) is absent will still report StatusOK.

Always cross-check `otel-merged.yaml` or `edot/otel-merged-actual.yaml` against `components-expected.yaml` to confirm all expected receivers are present in the running pipeline.

## Log-level strings

In NDJSON log lines, `log.level` is a string:

| Value | Severity |
|-------|---------|
| `"debug"` | Verbose diagnostic info; not normally present unless debug logging enabled |
| `"info"` | Normal operation events |
| `"warn"` | Something unexpected but non-fatal |
| `"error"` | A component or operation failed; investigation warranted |
| `"fatal"` | Process-level failure; agent or collector may be about to exit (log levels come from zap/logp: debug, info, warn, error, and the process-ending dpanic/panic/fatal) |

## Quick decode one-liner

```bash
# Decode all component states in state.yaml (requires kislyuk yq)
yq '.components[] | {id, state: .state.state, message: .state.message}' state.yaml

# Decode with numeric mapping using jq
jq '.components[] | {
  id,
  state: (.state.state | {
    "0":"STARTING","1":"CONFIGURING","2":"HEALTHY",
    "3":"DEGRADED","4":"FAILED","5":"STOPPING","6":"STOPPED"
  }[tostring] // "UNKNOWN(\(.))"),
  message: .state.message
}' state.yaml
```
