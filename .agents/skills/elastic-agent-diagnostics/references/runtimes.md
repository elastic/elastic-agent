# Component runtimes: OTel receiver, beat process, OS service

Timings below are given as the constant that defines them, with its value on main at the time of writing (2026-09); if a number matters to your conclusion, read the constant at the build's commit.

Not everything runs in the EDOT collector. Each component runs in one of three runtimes, and each has different logs, health reporting, and failure modes. Establish the runtime of every component involved **before** interpreting logs — the four-layer model (L1 supervisor → L2 collector core → L3 pipeline component → L4 beat) only fully applies to the OTel runtime.

| Runtime | What runs | Used for | Managed by |
|---|---|---|---|
| **otel** | the beat as a receiver (`<beat>receiver`) inside the `elastic-otel-collector` subprocess | beat inputs, by default (see below) | OTel manager (`internal/pkg/otel/manager/`) |
| **process** | a separate beat subprocess, `elastic-otel-collector <beat> -E …` (the beats ship inside the EDOT binary) | beat inputs that aren't in otel mode; other process components (e.g. `apm-server`, `fleet-server`, `cloudbeat`) | runtime manager, `CommandRuntime` (`pkg/component/runtime/command.go`) |
| **service** | an OS service installed and supervised by the agent — **Elastic Endpoint (Elastic Defend)** | `endpoint` | runtime manager, `ServiceRuntime` (`pkg/component/runtime/service.go`) |

The collector itself is always a subprocess on current versions (the in-process mode was removed in 9.3).

## Which runtime a beat input gets

There is an ongoing migration from process to otel; defaults differ by agent version (dynamic inputs below are one example), so check the bundle's `version.txt` and read the code at the build's commit when it matters. On main (`DefaultRuntimeConfig`, `pkg/component/component.go`):

- `filebeat`, `metricbeat`, `auditbeat`, `osquerybeat`, `packetbeat` inputs default to **otel**; `heartbeat` defaults to **process**. The global default is `process`.
- Beat receiver behaviour and the settings are documented in [docs/hybrid-agent-beats-receivers.md](../../../../docs/hybrid-agent-beats-receivers.md) (note: its defaults text lags main; `DefaultRuntimeConfig` is authoritative). Agent self-monitoring has its own switch, `agent.monitoring._runtime_experimental` (default `otel`; env `AGENT_MONITORING_RUNTIME_EXPERIMENTAL`).
- Because heartbeat has no beat-level default, it is exactly the beat that a global `agent.internal.runtime.default: otel` moves — that's what the Fleet runtime-switch tests set (`switchPolicyToOtelRuntime`).
- Overrides, highest precedence first: an input's own `_runtime_experimental: otel|process` → `agent.internal.runtime.output.<type>` → `agent.internal.runtime.<beat>.<input type>` → `agent.internal.runtime.<beat>.default` → `agent.internal.runtime.default`. Because `<beat>.default` is set to `otel`, setting only the global `default: process` does **not** move those beats back to process. Look for these keys in `computed-config.yaml` / `pre-config.yaml`.
- **Automatic fallback to process** when the component can't run in otel, logged by the coordinator:
  - `otel runtime is not supported for component <id>, switching to process runtime, reason: …` — e.g. an unsupported output type (only elasticsearch, logstash, kafka are supported) or unsupported output options (elasticsearch `indices`, `loadbalance: false`, …).
  - `Component <id> uses dynamic variable providers, switching to <runtime> runtime` (warn) — a component with inputs rendered from a dynamic provider (kubernetes, docker, `local_dynamic`; flagged *dynamic*, always) is moved to another runtime, because every change to it reloads the collector config, which is expensive. Whether this happens depends on the **version**: `agent.internal.runtime.dynamic_inputs` defaults to `process` in 9.3, 9.4 and 9.5 (**on by default**: dynamic components run as beat processes), and is empty on main / 9.6 since #15536 (2026-07-15; dynamic components stay otel). Resolution is per beat and input type, like `agent.internal.runtime`; `static_variables` can exempt inputs whose variables never change. Read `DefaultRuntimeConfig` at the build's commit, and see [docs/hybrid-agent-beats-receivers.md](../../../../docs/hybrid-agent-beats-receivers.md) §"Dynamic Inputs" (it doesn't state the default).
  - For monitoring: `otel runtime is not supported for monitoring output, switching to process runtime, reason: …`.

## Telling the runtime from a bundle

**Reliable:**

| Evidence | otel | process | service (Endpoint) |
|---|---|---|---|
| `state.yaml` `components[].state.version_info.name` | `beats-receiver` | `beat-v2-client` | `Endpoint` |
| `state.yaml` component `message` | `Healthy`, `Starting`, `Recoverable: …`, `Fatal: …` | `Healthy: communicating with pid '<n>'`, `Failed: pid '<n>' exited with code '<c>'`, … | `Healthy: communicating with endpoint service`, … |
| `otel-merged.yaml` | receivers `<beat>receiver/_agent-component/<id>/…`, pipeline `logs/_agent-component/<id>` | absent | absent |
| Where the component's own log lines are | `logs/*/elastic-otel-collector-*.ndjson`, with `otelcol.component.id` | `logs/*/elastic-agent-*.ndjson`, `log.source: <component id>` and no `otelcol.component.id` | `logs/services/endpoint-*.log` (Endpoint's own log) |
| Coordinator `Spawned new component <id>: …` | `STARTING` / `Starting`, or empty then `Healthy` after a runtime switch | `Starting: spawned pid '<n>'` | `Starting: endpoint service runtime` |

```bash
yq -r '.components[] | "\(.id)\t\(.state.version_info.name // "?")\t\(.state.state)\t\(.state.message[:80])"' "$BUNDLE_DIR/state.yaml"
```

**Not discriminating** — don't use them: `input_spec.binary_name` (`elastic-otel-collector` for beats in *both* runtimes; `endpoint-security` for Endpoint), the component `id`, `pid` (0 for beats in both runtimes; non-zero only for Endpoint), and the `component.*` / `log.source` log fields (set identically by both runtimes). `components-expected.yaml` has no runtime field.

`state.yaml` shows the runtime **at the time of the snapshot**. If the test switched runtimes, the logs contain both.

## Health reporting and failure signatures per runtime

- **otel**: the OTel manager polls the collector's healthcheck extension every second and maps pipeline `logs/_agent-component/<id>` status to component state; a component missing from the collector's status is reported STOPPED. After `maxFailuresDuration` (130 s) without an answer (`execution_subprocess.go`): `failed to connect to collector`. Collector crash loops (logger `otel_manager`): `collector exited with error (will try to recover in …)`, `collector recovery restarting, total retries: N`, `supervised collector (pid: N) exited with error: …`. One broken receiver can take down the whole collector, and with it every otel component — look for the first `failed to build pipelines` (may be logged at debug).
- **process**: gRPC check-ins. `Degraded: pid '<n>' missed 1 check-in`; after `maxCheckinMisses` (3, `runtime/manager.go`) `Failed: pid '<n>' missed 3 check-ins and will be killed`; unexpected exits as `Failed: pid '<n>' exited with code '<c>'`. A requested stop is SIGTERM, then SIGKILL after `ProcessStopTimeout` (30 s, `runtime/command.go`), and a clean one ends in `Stopped: pid '<n>' exited with code '0'`. Each process fails independently.
- **service**: see Endpoint below — check-ins, but FAILED only after a miss threshold scaled to the longest service operation timeout (see Endpoint below).

## Runtime switches

Tests that compare runtimes (`TestBeatsMetrics/otel|process|compare`, `TestMonitoringNoDuplicates`, `TestComponentWorkDir`, …; mostly `testing/integration/ess/beat_receivers_test.go` and the `*_monitoring_test.go` runners) switch a component between runtimes via policy. The old instance must reach STOPPED before the new one starts; the coordinator gives up waiting after `transitionTimeout` (`ProcessStopTimeout` + 3 s, `coordinator.go`) and force-applies. Log lines to look for:

- `Deferring OTel components until process instances stop` / `Deferring runtime components until OTel instances stop`
- `Component "<id>" stopped, N remaining before deferred update`
- `All process-to-OTel transitioning components have stopped in the process runtime, applying OTel update …` (and the OTel-to-process mirror)
- `Runtime transition timeout exceeded, force-applying deferred manager updates` (warn) — the old instance didn't stop in time; suspect it first
- `Runtime transitions still in progress, queuing new component model` / `All runtime transitions complete, applying queued component model`

Data duplicated or missing around a switch is often the transition itself (both instances briefly shipping, or neither), not a steady-state bug.

## Elastic Endpoint (Elastic Defend)

Service components in general are documented in [docs/component-specs.md](../../../../docs/component-specs.md) and `specs/endpoint-security.spec.yml` is the source of truth for Endpoint's operations, timeouts and proxied actions. Endpoint is an EDR product whose code is **not in this repo**. The agent installs it as an OS service (systemd unit `ElasticEndpoint` on Linux; a Windows service; launchd on macOS), passes it policy and connection info, and relays some actions to it. When the evidence points inside Endpoint itself, say so and stop — don't speculate about its internals.

**Lifecycle** (`ServiceRuntime`, `specs/endpoint-security.spec.yml`):
- On start the agent runs the installer shipped in its own components dir, `data/elastic-agent-<hash>/components/endpoint-security`: `verify`, and if that fails `install --upgrade --resources endpoint-security-resources.zip` (operation timeouts are in `specs/endpoint-security.spec.yml`: 600 s for install and uninstall). Logged as `check if endpoint service is installed` → `after check if endpoint service is installed, err: …` → `failed check endpoint service: … try install` (normal on first install: "Endpoint is not installed"). Connection info is served on a local socket (`.eaci.sock` under the agent's top path), not a TCP port.
- **Install failures don't mark the component FAILED.** The component can sit in `Starting` while the agent logs `failed to start endpoint service, err: …, restarting after waiting for <serviceRestartDelay>` (30 s) and retries. Search the logs; don't trust `state.yaml` alone.
- Health is by check-in (`defaultCheckServiceStatusInterval`, 30 s, `runtime/service.go`). `Degraded: endpoint service missed 1 check-in`, `Degraded: endpoint missed N check-ins`; `Failed: endpoint service missed N check-ins` only after about longest-operation-timeout ÷ check-in-interval misses (600 s ÷ 30 s = 20, ≈10 min; `TestServiceCheckinFailureTimeout` in `service_test.go` pins the arithmetic).
- **Removed, then back within seconds?** `Stopped: endpoint service runtime` followed shortly by `Spawned new component endpoint: Starting: endpoint service runtime` means a policy containing Endpoint was applied again after the removal — look for policy changes after it (playbooks §"Policy changes") and at the revision in `computed-config.yaml`.
- **Agent shutdown or restart only stops supervision; Endpoint keeps running.** Removing Endpoint from the policy (including via unenroll) runs `uninstall` (up to the spec's uninstall timeout): `stopping endpoint service runtime` → `endpoint service has checked in, send stopping state to service` (or `…had never checked in, proceed to uninstall`) → `uninstall endpoint service` → `Stopped: endpoint service runtime`, or `failed endpoint service uninstall, err: …`.
- `elastic-agent uninstall` uninstalls service components **first**, from the on-disk config, with `--uninstall-token`; if that fails, it prints `failed to uninstall component "endpoint": …`, restarts the agent service and leaves the agent installed on purpose.

**Upgrades.** The agent doesn't upgrade Endpoint explicitly: the new agent version ships a new installer, and the new agent's start runs `verify` / `install --upgrade`. With tamper protection, the agent forwards the signed UPGRADE action to Endpoint before switching its symlink; if that fails the upgrade fails with `pre-symlink callback failed: failed to notify units of proxied action: …`. If Endpoint reports FAILED during the watcher's grace period, the watcher rolls the agent back (`agent reported failed component(s) state`).

**Tamper protection.** Enabled per Defend policy. The policy's `signed` block (uninstall token hash, signing key) is copied into Endpoint's unit; Endpoint — not the agent — validates the uninstall token. UNENROLL, UPGRADE and MIGRATE are proxied actions (the spec's `proxied_actions`); with tamper protection, UNENROLL and UPGRADE are sent to Endpoint before the agent acts, and MIGRATE is refused. Protected agents refuse `install -f` over them and `uninstall` without the right token.

**In the bundle:**
- `components/endpoint/` — Endpoint's own diagnostics, returned to the agent's request: `policy_response.json` (per-action status of the applied policy; the source of Endpoint's `Applied policy …` DEGRADED messages — `jq '.Endpoint.policy.applied | {name, version, status}'` and `jq -r '.Endpoint.policy.applied.actions[] | select(.status != "success") | "\(.name) \(.status) \(.message)"'`), `elastic-endpoint.yaml`, `metrics.json`, `version.txt`, `system_info.txt`. `error.txt` containing `diagnostic action timed out, deadline is …` (`diagnosticTimeout`, 20 s; 60 s with CPU profiling) means Endpoint didn't answer.
- `logs/services/endpoint-*.log` — Endpoint's own log, **for the currently installed instance only**: an uninstall removes it, so after a remove-and-reinstall it starts at the reinstall and the agent-side lines are all you have for earlier events. ECS JSON with **nested** fields (`.log.level`, `.log.origin.file.name`), so the agent-log recipes that use `.["log.level"]` don't match it, and `logs/*/*.ndjson` globs don't include it:
  ```bash
  jq -r 'select(.log.level == "error" or .log.level == "warning") | "\(.["@timestamp"]) \(.log.level) \(.message[:200])"' "$BUNDLE_DIR"/logs/services/endpoint-*.log | head -50
  ```
- Agent-side lines about Endpoint have `log.logger: component.runtime.endpoint.service_runtime` (classified L1). **Everything the installer writes to stderr is logged at `error` level** with `context: "command output"`, whatever its content ("Wrote installation file …", "Successfully ran /bin/systemctl …") — hundreds of lines per install. Exclude exactly those from error counts and summaries (keep the rest of the logger: the lifecycle lines and real errors such as `failed accept conn info connection`), and read the level embedded in the message (`info:`, `debug:`, `error:`) when you do look at them:
  ```bash
  # errors, without installer output
  jq -r 'select(.["log.level"] == "error" and .context != "command output") | .message[:200]' \
    "$BUNDLE_DIR"/logs/*/*.ndjson | sort | uniq -c | sort -rn | head -20
  # the agent's view of Endpoint's lifecycle
  jq -r 'select(.["log.logger"] == "component.runtime.endpoint.service_runtime" and .context != "command output")
    | "\(.["@timestamp"]) \(.["log.level"]) \(.message[:160])"' "$BUNDLE_DIR"/logs/*/*.ndjson | sort
  ```
- The `endpoint` component is the only one with a real `pid` in `state.yaml`; `system/metrics-monitoring` has a unit `…-metrics-monitoring-endpoint_security` that monitors that process.

**Tests.** Most Endpoint tests are in `testing/integration/ess/endpoint_security_test.go` and `monitoring_endpoint_test.go`, group `fleet-endpoint-security` (job names contain `:fleet-endpoint-security`); the DEB/RPM upgrade tests (`TestUpgradeAgentWithTamperProtectedEndpoint_{DEB,RPM}`) run in the `deb`/`rpm` groups. Helpers: `installElasticDefendPackage`, `agentAndEndpointAreHealthy`, `addEndpointCleanup` (`endpoint_security_test.go`), `tools.GetUninstallToken`. Test cleanup and fixtures may run `/opt/Elastic/Endpoint/elastic-endpoint` directly — the agent itself never does.
