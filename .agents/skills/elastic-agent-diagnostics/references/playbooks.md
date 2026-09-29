# Diagnostics playbooks

Task-specific recipes. All commands assume `BUNDLE_DIR` is set to the extracted bundle root.

## 1. Quick triage (always run first)

Goal: in under a minute, know agent version, fleet status, all component states, and whether logs contain notable errors.

**Preferred — single command** (with `<DIAG>` = `<skill-base-dir>/bin/diag`, absolute path; never `~`):

```bash
<DIAG> triage <bundle>
```

That produces version, identity, fleet config, decoded top-level state, decoded per-component state, expected-vs-actual drift, and per-file log error/warn counts. Accepts either a `.zip` or an extracted directory.

**Manual equivalent (only if the helper is unavailable):**

```bash
echo "=== version ===" && cat "$BUNDLE_DIR/version.txt"
echo "=== package ===" && cat "$BUNDLE_DIR/package.version"

echo "=== state (top-level) ==="
yq '{state, message, fleet_state, fleet_message, log_level, "collector.status": .collector.status}' "$BUNDLE_DIR/state.yaml"

echo "=== components ==="
yq '.components[] | {id, state: .state.state, message: .state.message, pid: .state.pid}' "$BUNDLE_DIR/state.yaml"

diff -q "$BUNDLE_DIR/components-expected.yaml" "$BUNDLE_DIR/components-actual.yaml" \
  && echo "expected == actual" || echo "DRIFT: expected != actual (in-flight or stuck transition)"

echo "=== log error/warn counts ==="
for f in "$BUNDLE_DIR"/logs/*/*.ndjson; do
  errs=$(grep -c '"log.level":"error"' "$f" 2>/dev/null); errs=${errs:-0}
  warns=$(grep -c '"log.level":"warn"' "$f" 2>/dev/null); warns=${warns:-0}
  printf '%-80s err=%s warn=%s\n' "$(basename "$f")" "$errs" "$warns"
done
```

`yq` syntax assumed: kislyuk Python `yq` (a jq-wrapper that accepts pure jq filters). Mike Farah's Go `yq` uses different syntax — if you see `error: yq: error parsing filter`, you're hitting the Go variant; rewrite using its native `yq eval` form, or pipe through `python3 -c 'import yaml,sys,json; json.dump(yaml.safe_load(sys.stdin), sys.stdout)'` and use `jq`.

If everything is in state 2 / StatusOK and no errors → stop and tell the user the bundle looks healthy. Don't manufacture issues.

## 2. Log analysis

NDJSON logs are line-oriented JSON. Use `jq`, never `cat`.

**Preferred — `diag` subcommands** (with `<DIAG>` = `<skill-base-dir>/bin/diag`):

```bash
<DIAG> layer  <bundle> L1|L2|L3|L4 [<component>]
<DIAG> layers <bundle> [<component>]
<DIAG> logs   <bundle> [<component>] [--level error|warn] [--since T] [--until T]
<DIAG> errors <bundle> [--top N]
<DIAG> warnings <bundle> [--top N]
<DIAG> transitions <bundle> [<component>]
```

The raw `jq` recipes below show *what each subcommand does internally* and are useful when you need a query the helper doesn't expose.

### Partitioning logs by management layer

In hybrid mode (the common case), the agent has **four distinct management layers** that all log to the same NDJSON file:

```
1. elastic-agent supervisor (control plane)
   ↓ spawns / configures
2. OTel collector core framework
   ↓ runs
3. OTel pipeline components (receivers, processors, extensions)
   ↓ (for beat-based receivers) hosts
4. embedded beat internals (filebeat, metricbeat code)
```

Each adjacent pair of layers is a control boundary, and **discrepancies between adjacent layers are some of the strongest RCA signals.** A bug typically shows up as one layer thinking something happened that the next layer never observed.

**The layer-classification ladder.** Apply rules top-down — the first match wins. Note: filter priority does not follow layer order (L1→L4) because embedded beats (L4) must be matched before OTel core (L2) — they share the absence of `log.source` and `otelcol.component.id` but are distinguished by `service.name`.

| Priority | Layer (L#) | Filter | Examples |
|---|---|---|---|
| 1 | **L1 — Supervisor** | `.["log.source"] == "elastic-agent"` | "Spawned new component endpoint", "Component state changed (HEALTHY→STOPPED)", "Performance preset 'balanced' overrides..." |
| 2 | **L4 — Embedded beat** | `.["service.name"] in ("filebeat", "metricbeat")` | "Home path: ...", "Beat ID: ...", harvester/registrar lines |
| 3 | **L3 — OTel pipeline component** | `.["otelcol.component.id"] != null` | "Configured Beat processor", "registry bridge discovered initial stats metrics" |
| 4 | **L2 — OTel collector core** | else (no `log.source`, no `service.name`, no `otelcol.component.id`) | "Starting extensions...", "Everything is ready. Begin running and processing data.", "Config updated, restart service", "Starting shutdown..." |

Within layer 3, sub-divide by `otelcol.component.kind`: `receiver`, `processor`, `extension`. Within layer 4, look at `log.logger` — `edot.api` is the EDOT diagnostics endpoint; unset means the OTel collector framework itself.

**Caveat — supervisor-bridge logs.** A few supervisor packages emit lines without `log.source`. Most notably `log.logger == "component.runtime.endpoint.service_runtime"` (398 lines in the sample) is supervisor code (`pkg/component/runtime/service.go`) that captures and forwards stdout/stderr from the standalone endpoint service process. These will misclassify as layer 4 by the rules above. If `log.logger` starts with `component.runtime.`, treat it as layer 1.

### Per-component view

A given **component-id** (e.g. `filestream-monitoring`, `endpoint`) appears in multiple layers:

| Layer | What you'll see for `component.id == X` |
|---|---|
| 1 (supervisor) | `log.source == "elastic-agent"` lines tagged `.component.id == X` — the supervisor's view of X (state changes, spawn, stop). |
| 3 (receiver) | `otelcol.component.id` matching a name like `filebeatreceiver/_agent-component/X` — the receiver shell's startup/shutdown for X. |
| 4 (embedded beat) | `service.name == "filebeat"/"metricbeat"` *and* `.component.id == X` — the beat itself running inside the receiver. |

That's three views of the same component, each from one layer up. Pull them all to triangulate.

### Discrepancy patterns to hunt

These are the high-value findings. A bug typically shows up as one layer thinking something happened that the next layer never observed.

| Pair | Discrepancy | Likely cause |
|---|---|---|
| L1 → L2 | Supervisor: "Stopping collector" → Collector core: never logs `Starting shutdown...` | Supervisor failed to deliver the stop signal (IPC/socket bug). |
| L1 → L2 | Supervisor: "Config update sent" → Collector core: never logs `Config updated, restart service` | Config delivery bug; collector never picked up the new policy. |
| L2 → L3 | Collector core: `Starting shutdown...` → Receiver: continues logging activity | Receiver ignored the shutdown — receiver-side bug. |
| L2 → L3 | Collector core: ready → Receiver: never logs startup | Receiver failed to register with the pipeline. |
| L3 → L4 | Receiver shell: configured → Embedded beat: never logs `Beat ID: ...` | Receiver bridge broken; beat never got initialized. |
| L3 → L4 | Receiver: shutdown → Embedded beat: still emitting harvester/output lines | Beat ignored shutdown — possible deadlock in beat-side code. |
| L1 ↔ state.yaml | Supervisor: logs "FATAL"/panic for X → state.yaml: shows X HEALTHY | State is stale; supervisor hasn't observed the failure yet. |

These are *sequence* mismatches — verify them by reading the cross-layer interleaved timeline (next section), not by reading any one layer in isolation.

### Cross-layer interleaved timeline

To hunt discrepancies, look at all four layers in time order with explicit layer tags:

```bash
jq -c '. | {
  ts: .["@timestamp"],
  lvl: .["log.level"],
  layer: (
    if .["log.source"]=="elastic-agent"
       or ((.["log.logger"]//"") | startswith("component.runtime.")) then "L1-supervisor"
    elif .["service.name"] == "filebeat" or .["service.name"] == "metricbeat" then "L4-beat"
    elif .["otelcol.component.id"] then "L3-otel-component"
    else "L2-otel-core" end),
  cid: (.component.id // ""),
  otel: (.["otelcol.component.id"] // ""),
  msg: (.message[:120])
}' "$BUNDLE_DIR"/logs/*/*.ndjson
```

Filter to a window and a specific component to chase a specific transition:

```bash
CID=filestream-monitoring
START="2026-04-10T14:23:00Z"; END="2026-04-10T14:23:30Z"
jq -c --arg cid "$CID" --arg s "$START" --arg e "$END" '
  select(.["@timestamp"] >= $s and .["@timestamp"] <= $e) |
  select(.component.id == $cid or (.["otelcol.component.id"] // "") | contains($cid)) |
  {ts: .["@timestamp"], lvl: .["log.level"],
   layer: (
     if .["log.source"]=="elastic-agent" then "L1"
     elif .["service.name"]=="filebeat" or .["service.name"]=="metricbeat" then "L4"
     elif .["otelcol.component.id"] then "L3" else "L2" end),
   msg: .message[:120]}' "$BUNDLE_DIR"/logs/*/*.ndjson
```

Read the output top-to-bottom: each transition should produce activity in the layer being driven (L1 emits, L2/L3/L4 react). Silence in the next layer after a directive is the signal.

### List components seen in logs

```bash
jq -r 'select(.component.id) | .component.id' "$BUNDLE_DIR"/logs/*/*.ndjson | sort | uniq -c | sort -rn
```

This will surface components that were running earlier in this agent's life but are no longer in `state.yaml` (e.g. ones that were removed) — useful for tracing removal flows.

### Per-component health check

For each component-id, check:
- Did it reach `HEALTHY` at any point? `select(.component.state == "HEALTHY")`
- Did it ever go `DEGRADED` / `FAILED`? `select(.component.state == "FAILED" or .component.state == "DEGRADED")`
- What was its terminal state in the logs? Pick the latest `.component.state` event.

```bash
CID=endpoint
jq -r --arg cid "$CID" 'select(.component.id==$cid and .component.state) |
  "\(.["@timestamp"])\t\(.component.state)\(if .component.old_state then "  (was "+.component.old_state+")" else "" end)\t\(.message[:80])"' \
  "$BUNDLE_DIR"/logs/*/*.ndjson
```

### Top distinct error messages

```bash
jq -r 'select(.["log.level"]=="error") | .message' "$BUNDLE_DIR"/logs/*/*.ndjson \
  | sort | uniq -c | sort -rn | head -20
```

### Errors with timestamps and origin (best for triage)

```bash
jq -r 'select(.["log.level"]=="error") |
  "\(.["@timestamp"])  \(.["log.origin"]["file.name"]):\(.["log.origin"]["file.line"])  \(.message)"' \
  "$BUNDLE_DIR"/logs/*/*.ndjson | head -50
```

### All log lines mentioning a specific component

```bash
jq -c --arg cid "filestream-monitoring" \
  'select((.["component.id"]==$cid) or (.message | contains($cid)))' \
  "$BUNDLE_DIR"/logs/*/*.ndjson
```

### Time-bounded slice (e.g. around `state.yaml`'s `collector.timestamp`)

```bash
jq -c --arg start "2026-04-10T14:27:00Z" --arg end "2026-04-10T14:28:30Z" \
  'select(.["@timestamp"] >= $start and .["@timestamp"] <= $end)' \
  "$BUNDLE_DIR"/logs/*/*.ndjson
```

### Sequence of state transitions

```bash
jq -c 'select(.message | test("state changed|Component state changed|Unit state changed"; "i"))' \
  "$BUNDLE_DIR"/logs/*/*.ndjson
```

## 3. Component & policy inspection

**Preferred:** `<DIAG> components <bundle>`, `<DIAG> policy <bundle>`, `<DIAG> drift <bundle>`, `<DIAG> streams <bundle>` (with `<DIAG>` = `<skill-base-dir>/bin/diag`). Raw queries below for ad-hoc cases.

### What does the policy compile into?

```bash
yq '.components[] | {
  id,
  input_type,
  output_type,
  output_name,
  binary: .input_spec.binary_name,
  units: [.units[] | {id, type}]
}' "$BUNDLE_DIR/components-actual.yaml"
```

(`type` on a unit is a `UnitType` integer: `0` = INPUT, `1` = OUTPUT.)

### What streams does each input have?

The compiled `components-*.yaml` only carries unit ids/types — the per-stream config lives in `computed-config.yaml`. For *runtime* stream status, use `state.yaml`:

```bash
yq '.components[] | .id as $cid |
    .state.units | to_entries[] |
    select(.value.payload.streams) |
    {component: $cid, unit: .key,
     streams: (.value.payload.streams | to_entries | map({id: .key, status: .value.status}))}' \
  "$BUNDLE_DIR/state.yaml"
```

(Use `select(.value.payload.streams)` rather than `select(... != null)` — bare `!=` clashes with zsh history expansion.)

### What outputs are defined?

Each component's output is summarised at the component level:

```bash
yq '[.components[] | {id, output_name, output_type}] | unique_by(.output_name)' \
  "$BUNDLE_DIR/components-actual.yaml"
```

For raw output configuration (hosts, credentials redacted), look in `computed-config.yaml` under `outputs:`.

### Diff `expected` vs `actual` (when drift detected)

```bash
diff -u "$BUNDLE_DIR/components-expected.yaml" "$BUNDLE_DIR/components-actual.yaml"
```

A small diff (a few units) typically means a recent policy change; a large diff suggests the runtime is stuck.

### Per-unit failure messages

```bash
yq '[.components[] | .id as $cid |
     .state.units | to_entries[] |
     select((.value.state | tonumber) > 2) |
     {component: $cid, unit: .key, state: .value.state, message: .value.message}]' \
  "$BUNDLE_DIR/state.yaml"
```

(States 3=DEGRADED, 4=FAILED, 5=STOPPING, 6=STOPPED — all "not steady-state healthy". Adjust the threshold per your investigation.)

## 4. Pprof analysis

All pprof files (including `.gz`) work directly with `go tool pprof`.

**Preferred:** `<DIAG> pprof <bundle> <profile> [--edot] [pprof-args...]` (with `<DIAG>` = `<skill-base-dir>/bin/diag`). Profile is one of `heap|allocs|goroutine|cpu|block|mutex|threadcreate`. With no extra args defaults to `-top -nodecount 20`. Add `--edot` to point at the EDOT collector's profile in `<bundle>/edot/`. The raw recipes below are still useful when you need flag combinations the helper doesn't pass through.

### Goroutine leaks

```bash
# Total goroutine count and top stacks
go tool pprof -top -nodecount 30 "$BUNDLE_DIR/goroutine.pprof.gz"

# Group identical stacks
go tool pprof -traces "$BUNDLE_DIR/goroutine.pprof.gz" | head -200
```

If the same stack appears thousands of times → leak. Identify the function and search the codebase for who spawned that goroutine.

### Memory growth

```bash
# Top in-use heap
go tool pprof -top -inuse_space -nodecount 20 "$BUNDLE_DIR/heap.pprof.gz"

# Top by allocation count (helps catch many-small-allocs patterns)
go tool pprof -top -inuse_objects -nodecount 20 "$BUNDLE_DIR/heap.pprof.gz"

# Listing for a specific function
go tool pprof -list 'github.com/elastic/elastic-agent/internal/.*' "$BUNDLE_DIR/heap.pprof.gz"
```

### Allocation pressure (orthogonal to live heap)

```bash
go tool pprof -top -alloc_space -nodecount 20 "$BUNDLE_DIR/allocs.pprof.gz"
```

### Block / mutex (often empty)

```bash
go tool pprof -top "$BUNDLE_DIR/block.pprof.gz"   # blocked stacks
go tool pprof -top "$BUNDLE_DIR/mutex.pprof.gz"   # contended mutex holders
```

If both show "Total samples = 0", the corresponding profiling rate wasn't enabled — that's expected on most production bundles.

### CPU (only present with `--cpu-profile`)

```bash
go tool pprof -top -nodecount 20 "$BUNDLE_DIR/cpu.pprof"
```

### EDOT collector pprof

Same commands, just point at `$BUNDLE_DIR/edot/<profile>.profile.gz` instead. Investigate these separately from agent pprof — they are different processes.

## 5. Upgrade & watcher

If `version.txt:version` ≠ `package.version`, an upgrade is in progress.

```bash
# Watcher logs
cat "$BUNDLE_DIR"/logs/*/elastic-agent-watcher-*.ndjson | jq -c 'select(.["log.level"]!="info" or (.message | test("rollback|upgrade|grace"; "i")))'

# Upgrade-related agent logs
jq -c 'select(.message | test("upgrade|rollback|watcher|grace"; "i"))' \
  "$BUNDLE_DIR"/logs/*/elastic-agent-*.ndjson
```

Look for: "Upgrade Watcher invoked" → "Watcher detected unhealthy" → "Rollback initiated" sequences.

## 6. Beat-based component telemetry

For beat-based components (filestream, metricbeat, etc.):

```bash
# Pipeline health
jq '.libbeat.pipeline.events' "$BUNDLE_DIR/components/<id>/beat_metrics.json"

# Output stats
jq '.libbeat.output' "$BUNDLE_DIR/components/<id>/beat_metrics.json"

# Per-input metrics (filebeat-like)
jq '.' "$BUNDLE_DIR/components/<id>/<unit-id>/input_metrics.json"
```

Key signals:
- `libbeat.pipeline.events.dropped > 0` → backpressure, output couldn't keep up.
- `libbeat.pipeline.events.failed > 0` → output rejected events.
- `libbeat.output.read.errors` / `write.errors` → connectivity issue with output.

## 7. Filebeat registry inspection

If a filebeat-based component has `registry.tar.gz`:

```bash
mkdir -p "$BUNDLE_DIR/_registry-extracted"
tar -xzf "$BUNDLE_DIR/components/<id>/<unit-id>/registry.tar.gz" -C "$BUNDLE_DIR/_registry-extracted"
ls "$BUNDLE_DIR/_registry-extracted"

# Most recent state for a file
jq 'select(.k | test("filestream::"))' "$BUNDLE_DIR/_registry-extracted/filebeat/log.json"
```

A registry larger than 20MB will be missing — the agent skips it and logs a warning. Look in the agent log for `"registry too large"`-style messages.
