# State Enumerations

Decoded reference for the integer state values that appear throughout `state.yaml` and the agent logs. Use this file when reading raw YAML/JSON — `state.yaml` stores these as integers.

The integer states in `state.yaml` — the `cproto.State` enum (0 STARTING … 8 ROLLBACK) used by agent, component and unit states, and the OTel collector status — are decoded in [docs/diagnostics.md](../../../../docs/diagnostics.md) §"State values", including the caveat that `collector.status: 2` doesn't mean all expected receivers are running.

Interpretation notes:

- For managed agents, inspect `fleet_state` together with `fleet_message` for connection problems. Standalone agents report STOPPED with `Not enrolled into Fleet`. After an unenroll the Fleet gateway is stopped and `fleet_state` / `fleet_message` can stay frozen (often `2` / `Connected`).
- A component stuck at **5 (STOPPING)** is a common failure mode — the supervisor told it to stop but it never acknowledged. Look for cross-layer discrepancies between L1 and L2/L3.
- Always cross-check `otel-merged.yaml` or `edot/otel-merged-actual.yaml` against `components-expected.yaml` to confirm all expected receivers are in the running pipeline.

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
