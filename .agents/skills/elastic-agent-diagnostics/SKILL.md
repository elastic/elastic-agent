---
name: elastic-agent-diagnostics
description: Analyze an elastic-agent diagnostics bundle (the .zip produced by `elastic-agent diagnostics`). Use when the user provides a bundle path or asks to triage agent state, parse logs, inspect configs/components, or analyze pprof profiles from a bundle.
---

# Elastic Agent diagnostics analysis

Help a developer investigate an elastic-agent issue from a diagnostics bundle. The bundle is produced by `elastic-agent diagnostics` and contains the agent's state, logs, configs, component info, and Go pprof profiles.

## Inputs you'll get

One of:
- A path to a `.zip` bundle (e.g. `/path/to/elastic-agent-diagnostics-<timestamp>.zip`).
- A path to an already-extracted directory.
- A Buildkite build URL or artifact reference — bundles are stored in GCS and must be fetched with the Google Cloud CLI (see below).

If neither is obvious from the user's message, ask.

## Fetching Buildkite artifacts from GCS

Buildkite artifacts are stored in Google Cloud Storage (GCS). You need the `gcloud` CLI (`google-cloud-cli` package) to download them — `curl`/`wget` won't work against these buckets.

### Preflight check — run this first, before any triage

Before attempting to download or analyze a bundle that came from Buildkite, verify GCS access:

```bash
# 1. gcloud present?
command -v gcloud || echo "ERROR: gcloud not found — install google-cloud-cli"

# 2. authenticated?
gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>&1

# 3. application-default credentials (needed for storage)?
gcloud auth application-default print-access-token &>/dev/null \
  && echo "ADC OK" \
  || echo "WARNING: no ADC — run: gcloud auth application-default login"
```

If step 1 fails: tell the user to install `google-cloud-cli` and re-run.  
If step 2 shows no active account: tell the user to run `gcloud auth login`.  
If step 3 warns: tell the user to run `gcloud auth application-default login`.

Only proceed to download once all three checks pass.

### Downloading the artifact

Use `gcloud storage cp` (preferred) or the legacy `gsutil cp`:

```bash
# gcloud storage (modern, faster)
gcloud storage cp "gs://<bucket>/<path>/elastic-agent-diagnostics-*.zip" /tmp/

# gsutil (legacy fallback, same credentials)
gsutil cp "gs://<bucket>/<path>/elastic-agent-diagnostics-*.zip" /tmp/
```

If the user gives a Buildkite build URL rather than a GCS path, use the Buildkite CLI (`bk`) to locate the artifact path:

```bash
bk artifact download "elastic-agent-diagnostics-*.zip" /tmp/ --build <build-id>
```

After downloading, proceed with the normal `diag triage <bundle>` flow.

## Use the `diag` helper as the primary tool

This skill ships a helper at `bin/diag` (relative to this skill's base directory). **Prefer it over raw `jq`/`yq`/`unzip` calls** — it accepts either a `.zip` or an extracted directory, handles extraction transparently, and encapsulates all the glob and filter expressions so each invocation is a single named command (one approval covers all uses of that subcommand).

**Path requirement.** Always invoke the helper with its **absolute path**. Construct it from this skill's base directory — the absolute path the Skill tool printed when it launched this skill (look for the line `Base directory for this skill: <abs-path>`). Assigning the absolute path to a variable for re-use is fine; **do not** use `~` (the permission parser can't statically resolve tilde, which forces a prompt).

Subcommands (replace `<DIAG>` with `<skill-base-dir>/bin/diag`):

```bash
<DIAG> help
<DIAG> triage <bundle>
<DIAG> state <bundle>
<DIAG> components <bundle>
<DIAG> transitions <bundle> [<component>]
<DIAG> layer <bundle> L1|L2|L3|L4 [<component>]
<DIAG> layers <bundle> [<component>]
<DIAG> logs <bundle> [<component>] [--level X] [--since T] [--until T]
<DIAG> errors <bundle> [--top N]
<DIAG> pprof <bundle> heap|allocs|goroutine|cpu|block|mutex|threadcreate [--edot] [pprof-args...]
```

Drop to raw `jq`/`yq` only when the question is genuinely ad-hoc and no subcommand fits.

## How to use this skill

0. **If the bundle came from Buildkite:** run the GCS preflight check above before doing anything else. Download the artifact once all three checks pass.
1. Run `diag triage <bundle>` first. That's almost always the right starting point.
2. Skim [references/bundle-layout.md](references/bundle-layout.md) for what each file holds.
3. Decode any state integers via [references/state-enums.md](references/state-enums.md) — though `diag state` already does this for you.
4. For deeper analysis pick the relevant playbook from [references/playbooks.md](references/playbooks.md):
   - **Quick triage** — single-shot health snapshot.
   - **Log analysis** — error/warning extraction, partitioning, cross-layer timeline.
   - **Component & policy inspection** — what's expected vs running, what each component does.
   - **pprof analysis** — CPU, memory, goroutine, mutex, block profiles.
   - **Upgrade & watcher** — upgrade failures and rollbacks.

## House rules

- **Don't cat large log files.** Daily NDJSON logs can be hundreds of KB to MBs. Use `jq` or `grep` to filter first, then `Read` the filtered output.
- **Don't dump pprof binary content.** Always go through `go tool pprof` with `-top`, `-list <symbol>`, `-text`, or `-traces`.
- **Redaction is already applied.** Fields like passwords, tokens, API keys, certs appear as `<REDACTED>`. Don't try to recover them — note their presence and move on.
- **`components-expected.yaml` and `components-actual.yaml`** are usually byte-identical when the agent has converged. A diff between them indicates an in-flight reconfiguration or a stuck applier — that diff itself is the signal.
- **Time correlation.** Log timestamps, `state.yaml` `collector.timestamp`, and the bundle filename's timestamp are all the same UTC source of truth. Correlate explicitly when sequencing events.
- **Bundle is a snapshot, not a stream.** `state.yaml` reflects the moment `diagnostics` ran. Do not infer trends from a single bundle — only the logs cover history.

## Reporting findings

Default to a short structured summary:
- **Agent**: version, mode (managed/standalone), Fleet status, overall state
- **Components**: count, any not in HEALTHY state (with their messages)
- **Notable log activity**: counts of errors/warnings, top distinct messages
- **Pprof red flags** (only if perf is the question)
- **Hypothesis / next step**

Cite file paths inside the bundle the same way you'd cite source files: `state.yaml:12`, `logs/elastic-agent-9.4.0-SNAPSHOT-1ae81b/elastic-agent-20260410-1.ndjson`, etc. The user can open these directly.
