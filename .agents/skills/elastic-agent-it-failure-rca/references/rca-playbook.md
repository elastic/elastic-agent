# RCA Playbook

## RCA report structure

Every RCA ends with a structured report. Fill each section from evidence, not from hypothesis.

---

**Failure mode**
One sentence: what assertion failed and what was the symptom.
> Example: "The OTel subtest timed out after 10 minutes because no `network_traffic` documents appeared in Elasticsearch — pbreceiver was never added to the OTel pipeline."

**Evidence chain**
Bullet list. Each bullet cites a specific file + finding. Include line numbers or log timestamps when possible. The format `file:line_or_timestamp: finding` makes items click-through friendly.

```
- state.yaml: packet-default absent from actual components; only filestream-monitoring and http/metrics-monitoring present
- components-expected.yaml: packet-default listed with binary_name: elastic-otel-collector — agent expected it to run as OTel receiver
- otel-merged.yaml: no packetbeatreceiver in running OTel config (0 matches for "packet")
- internal/pkg/otel/translate/otelconfig.go:511: getReceiverTypeForComponent switch has no "packetbeat" case → returns error
- internal/pkg/otel/manager/manager.go:~230: buildMergedConfig error → reportErr + continue, m.mergedCollectorCfg never updated
```

**Suspected cause**
Your best hypothesis. Distinguish:
- **Agent bug**: deterministic misbehaviour in agent code (wrong state transition, missing switch case, incorrect error handling)
- **Test bug**: assertion too strict, timeout too short, timing assumption wrong
- **Infra/environment**: network flap, cloud resource limit, slow VM

Label which you think it is and why.

**Confidence**
`high` / `medium` / `low`. State what would raise it (e.g. "medium — would be high if I could confirm pbreceiver was never started by checking the full agent log timeline, but the bundle's log was truncated").

**Next investigation step**
One concrete action. Stop here — do not propose code changes in the RCA.
> Example: "Read `internal/pkg/otel/translate/otelconfig.go:500-525` to confirm the switch statement is the only codepath that determines the receiver type, then check git log on that file for recent changes."

---

## Per-component log verification

For each component ID seen in `state.yaml` or the logs, run these queries in order. The goal is to confirm each layer either behaved correctly or identify the layer where behaviour diverged.

The queries use the `cid`/`layer` definitions from the diagnostics skill's playbook §"Partitioning logs by management layer" — write them to `$WORK/layers.jq` first. `BUNDLE_DIR` is the extracted bundle; `WORK` a scratch dir.

### Step 1 — L1 supervisor view

```bash
jq -r -L "$WORK" --arg l L1 --arg c <component-id> 'include "layers";
  select(layer == $l and (cid == $c or ((.["otelcol.component.id"] // "") | contains($c)) or .["log.source"] == $c))
  | [.["@timestamp"], .["log.level"], .message[:160]] | @tsv' "$BUNDLE_DIR"/logs/*/*.ndjson | sort
```

Expected sequence for a healthy start:
```
coordinator: Component state changed ... state=Starting
coordinator: Component state changed ... state=Running/Healthy
```

Expected sequence for a clean stop:
```
coordinator: Stopping component <component-id>
coordinator: Component state changed ... state=Stopped
```

Flag if: supervisor logs a stop but the component never reaches Stopped; or the component appears in `components-expected.yaml` but never appears in any L1 log.

### Step 2 — L3 receiver/process view

```bash
jq -r -L "$WORK" --arg l L3 --arg c <component-id> 'include "layers";
  select(layer == $l and (cid == $c or ((.["otelcol.component.id"] // "") | contains($c)) or .["log.source"] == $c))
  | [.["@timestamp"], .["log.level"], .message[:160]] | @tsv' "$BUNDLE_DIR"/logs/*/*.ndjson | sort
```

For OTel-mode components (binary_name: elastic-otel-collector), the receiver shell logs come from the OTel collector process. Look for:
- `Starting <receivertype> receiver for component <component-id>`
- `Stopping <receivertype> receiver`

For process-mode components (binary_name: filebeat/metricbeat/packetbeat), look for the beat's own startup lines (see L4 below).

### Step 3 — L4 embedded beat view (when applicable)

```bash
jq -r -L "$WORK" --arg l L4 --arg c <component-id> 'include "layers";
  select(layer == $l and (cid == $c or ((.["otelcol.component.id"] // "") | contains($c)) or .["log.source"] == $c))
  | [.["@timestamp"], .["log.level"], .message[:160]] | @tsv' "$BUNDLE_DIR"/logs/*/*.ndjson | sort
```

A successfully started beat logs these early lines:
```
Beat ID: <uuid>
Home path: [<path>] Config path: [<path>] ...
Data path: [<path>]
```

A cleanly stopped beat logs:
```
Exiting: bye
```

If L3 shows the receiver started but L4 has no "Beat ID:" line, the beat never initialised inside the receiver — the receiver bridge is broken.

### Step 4 — Cross-layer interleaved timeline

```bash
jq -r -L "$WORK" --arg c <component-id> 'include "layers";
  select(cid == $c or ((.["otelcol.component.id"] // "") | contains($c)) or .["log.source"] == $c)
  | [.["@timestamp"], layer, .["log.level"], .message[:140]] | @tsv' "$BUNDLE_DIR"/logs/*/*.ndjson | sort
```

This interleaves L1/L2/L3/L4 lines tagged with their layer. Look for the time gap between a supervisor action (L1) and the corresponding reaction in L2/L3. A gap > ~5 seconds is suspicious; no reaction at all is the smoking gun.

## Discrepancy patterns to hunt

These cross-layer patterns are the most reliable indicators of where a bug lives.

| Pattern | Likely cause |
|---|---|
| L1 "Stopping component" → no L2 shutdown log | Supervisor failed to deliver stop signal to OTel manager; check `applyOTelUpdate` / `Update` channel logic |
| L2 "Starting shutdown" → L3 receiver keeps logging activity | Receiver ignored the collector shutdown signal; check receiver's `Shutdown()` implementation |
| L3 receiver configured in `otel-merged.yaml` → no L4 "Beat ID:" | Receiver bridge broken; beat never initialised. Could be a config translation error or a missing receiver factory registration |
| L4 beat logs clean "Exiting: bye" → L1 component still in STOPPING | Supervisor state-propagation bug; beat exited but the agent's runtime manager didn't detect it |
| Component in `components-expected.yaml` → absent from `components-actual.yaml` AND absent from `otel-merged.yaml` | Config translation failure upstream; check `GetOtelConfig` / `buildMergedConfig` error path |
| `otel.yaml` shows "no active OTel configuration" | The OTel config provider never received a valid config; check `StdinGobProvider` and the `Update` → `buildMergedConfig` path |

## Partitioning logs by management layer

Layer is identified by structured fields — apply top-down, first match wins. The diagnostics skill's playbook §"Partitioning logs by management layer" has the full ladder with rationale and the reusable `jq` definitions.

| Layer | Filter |
|---|---|
| L1 — supervisor | `log.source == "elastic-agent"`, or `log.logger` starts with `"component.runtime."` (supervisor-bridge lines) |
| L4 — beat | `service.name` is a beat (`filebeat`, `metricbeat`, `heartbeat`, …); checked before L3 because embedded-beat lines also carry `otelcol.component.id` |
| L3 — OTel pipeline component | `otelcol.component.id` set (e.g. `"filebeatreceiver/_agent-component/filestream-monitoring"`) |
| L2 — OTel collector core | else (`service.name == "elastic-otel-collector"`, no `otelcol.component.id`) |

Don't match on the `log.logger` package name alone — it is not a reliable layer discriminator across code paths.

## Timing the failure

Note the test's observation window: from the moment it starts waiting for the condition it later asserts on (`captureStart`, "waiting for …" `t.Log` lines, or the setup step in the test source) to the failure. Log lines in the bundle inside that window are in scope; earlier lines are setup.

```bash
# Failure time: the gotestsum "fail" event (JUnit testcases have no timestamp)
jq -r --arg t "TestName/subtest" 'select(.Action=="fail" and .Test==$t) | .Time' "$RCA_DIR"/build/*.out.json

# Start of the window, from the test's own log lines
jq -j --arg t "TestName/subtest" 'select(.Action=="output" and .Test==$t) | "\(.Time[11:23]) \(.Output)"' \
  "$RCA_DIR"/build/*.out.json | grep -i -e "captureStart" -e "capture start" -e "starting capture" -e "waiting for"
```

## When there is no diagnostics bundle

Normal when the failure happened before the agent was installed (install command failed, package manager error, ESS/Fleet provisioning failed) or before the fixture collected diagnostics. Then:

- **Job log** — setup steps from `.buildkite/scripts/`, VM image name, agent version, the failing command's full output.
- **Sibling tests in the same job** — list every `fail` event with its time. Unrelated tests failing within the same window, with the same error, is an environment problem.
- **Retry vs first attempt** — a fresh VM passing on retry points at transient environment state; failing again points at something persistent (image, branch, test).
- **Fixture code** — `pkg/testing/fixture_install.go` and friends: does the failing step retry, wait, or fail on first error?
- **History** — the same job name across recent builds and branches ([locating-the-failure.md](locating-the-failure.md) §"Finding other occurrences").

## Common false trails

- **"IsHealthy returned true" does not mean all components are running.** The agent reports HEALTHY based on the components it is tracking. A component that never enters the OTel pipeline is never tracked, so it does not affect the health status. Always cross-check `components-actual.yaml` against `components-expected.yaml`.
- **An empty `otel.yaml` is normal** when the agent is not in OTel runtime mode. The merged config in `otel-merged.yaml` (or `edot/otel-merged-actual.yaml`) is the running config.
- **A `collector.status: 2` (HEALTHY) in `state.yaml` means the collector process is healthy**, not that all expected receivers are running. A collector with only monitoring receivers can be HEALTHY while the data receiver is absent.
- **Multiple bundles at similar timestamps**: if a test creates two agents (e.g. fleet-server + agent under test), both produce diagnostics at roughly the same time. The bundle without fleet-server paths in its config is the agent under test.
