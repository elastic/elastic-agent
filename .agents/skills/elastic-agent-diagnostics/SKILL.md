---
name: elastic-agent-diagnostics
description: Analyze an elastic-agent diagnostics bundle (the .zip produced by `elastic-agent diagnostics`). Use when the user provides a bundle path or asks to triage agent state, parse logs, inspect configs/components, or analyze pprof profiles from a bundle.
---

# Elastic Agent diagnostics analysis

Help a developer investigate an elastic-agent issue from a diagnostics bundle. The bundle is produced by `elastic-agent diagnostics` and contains the agent's state, logs, configs, component info, and Go pprof profiles.

## Inputs

- A path to a `.zip` bundle, or an already-extracted directory.
- A bundle that lives in CI (a Buildkite build/job URL or a `[Flaky Test]` issue): fetching it is the `elastic-agent-it-failure-rca` skill's job — its `references/access.md` and `references/artifacts.md` cover the GCS download, which is the only one that works. If you are here without that context, get the bundle first, then come back with a local path.

If it's not obvious which bundle to analyze, ask.

## Setup

Bundles have their files at the zip root. Extract once into a scratch directory and work on the directory:

```bash
WORK=<scratch dir>                      # for extracted bundles and helper files; never write next to the user's files
BUNDLE_DIR="$WORK/<bundle-name>"        # or the user's already-extracted directory
unzip -q -o <bundle>.zip -d "$BUNDLE_DIR"
```

Tools: `jq` for NDJSON logs and JSON; `yq` for YAML. The recipes assume kislyuk's Python `yq` (a jq wrapper — accepts jq filters). If `yq --help` mentions `eval`/mikefarah, it's the Go variant: use `yq -o=json '.' <file> | jq '<filter>'` instead. `go tool pprof` for profiles.

## How to use this skill

1. **Quick triage first** — [references/playbooks.md](references/playbooks.md) §1. Version, agent and Fleet state, per-component state, expected-vs-actual drift, per-file error/warning counts. If everything is healthy and there are no errors, say so and stop — don't manufacture issues.
2. Skim [references/bundle-layout.md](references/bundle-layout.md) for what each file holds.
3. Decode state integers with [references/state-enums.md](references/state-enums.md).
4. Go deeper with the relevant playbook section:
   - **Log analysis** — errors/warnings, partitioning by management layer (L1–L4), cross-layer timeline, state transitions.
   - **Component & policy inspection** — what's expected vs running, what each component does.
   - **pprof analysis** — CPU, memory, goroutine, mutex, block profiles.
   - **Upgrade & watcher** — upgrade failures and rollbacks.
   - **Beat telemetry / registry** — pipeline and output counters, filebeat registry.

## House rules

- **Don't cat large log files.** Daily NDJSON logs can be hundreds of KB to MBs. Filter with `jq` or `grep` first, then read the filtered output.
- **Don't dump pprof binary content.** Always go through `go tool pprof` with `-top`, `-list <symbol>`, `-text`, or `-traces`.
- **Redaction is already applied.** Passwords, tokens, API keys, and certs appear as `<REDACTED>`. Don't try to recover them — note their presence and move on.
- **`components-expected.yaml` and `components-actual.yaml`** are usually byte-identical when the agent has converged. A diff between them indicates an in-flight reconfiguration or a stuck applier — that diff itself is the signal.
- **Time correlation.** Log timestamps, `state.yaml` `collector.timestamp`, and the bundle filename's timestamp are all UTC. Correlate explicitly when sequencing events.
- **Bundle is a snapshot, not a stream.** `state.yaml` reflects the moment `diagnostics` ran. Only the logs cover history.

## Reporting findings

Default to a short structured summary:
- **Agent**: version, mode (managed/standalone), Fleet status, overall state
- **Components**: count, any not HEALTHY (with their messages)
- **Notable log activity**: error/warning counts, top distinct messages
- **Pprof red flags** (only if performance is the question)
- **Hypothesis / next step**

Cite file paths inside the bundle the way you'd cite source files — `state.yaml:12`, `logs/elastic-agent-9.6.0-SNAPSHOT-3152ee/elastic-agent-20260928-1.ndjson` — so the user can open them directly.
