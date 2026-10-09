---
name: elastic-agent-it-failure-rca
description: Root-cause an elastic-agent integration test failure from CI. Use when the user provides a flaky-test issue from elastic/elastic-agent (e.g. "look at #14049"), a Buildkite build or job URL, or a local artifacts directory, and wants a structured RCA report.
---

# Elastic Agent integration-test failure RCA

End-to-end root-cause analysis for an elastic-agent integration test failure in CI. The evidence chain is:

```
GitHub issue ─► Buildkite Test Engine run ─► Buildkite build + job ─► job log + artifacts (in GCS)
            ─► JUnit / gotestsum output / diagnostics bundle ─► test + agent source, git and CI history ─► report
```

Each hop needs a different kind of access. Most of the practical difficulty is in the plumbing, not the diagnosis, so do step 1 properly before anything else.

## Inputs accepted

1. **GitHub issue** — `#14049`, `elastic/elastic-agent#14049`, or a URL. Preferred: it names the test and links the failing run(s).
2. **Buildkite build URL**, with or without `?jid=<job-uuid>`.
3. **Local artifacts** — a directory the user already downloaded, or a diagnostics `.zip`. Skip to step 4.

If it's unclear which one the user has, ask.

## 1. Access preflight — find out what you have, then ask once for what's missing

| Capability | Needed for | Any of these works |
|---|---|---|
| **GitHub read** | the issue body + comments | GitHub MCP tools · `gh` · unauthenticated `curl` to api.github.com (public repo) |
| **Buildkite API** | Test Engine runs, builds, jobs, job logs, artifact metadata | Buildkite MCP tools · `bk api` · `BUILDKITE_API_TOKEN` + `curl` |
| **GCS read** | artifact *contents* (JUnit, gotestsum JSON, diagnostics zips) | `gcloud storage` — **nothing else works**, see below |

Rules:
- **Use whatever is already there.** Check which MCP tools are loaded, which CLIs are on `PATH`, and whether the relevant env vars are *set* (never print their values). Don't insist on one particular provider.
- **Probe with the real operation**, not an auth-status command: fetch the issue, fetch the build, list the job's objects in GCS. Status commands give both false positives and false negatives here.
- **Buildkite-mediated artifact downloads are a trap.** `download_url` redirects to `storage.cloud.google.com`, which needs a browser session. `curl -L`, `bk artifacts download`, and anything else following that redirect **save a Google sign-in HTML page under the artifact's name and report success**. Always fetch artifact bytes with `gcloud storage cp` from `gs://buildkite-elastic-agent/…`, and validate every file (step 3).
- **Collect every gap before stopping**, then send one message listing what's missing, the exact command to fix each (e.g. `! gcloud auth login` — the `!` prefix runs it in the user's session, needed for interactive logins), and what you can still do without it.

Provider-specific commands, probes, known failure modes, and the degraded modes available with partial access: [references/access.md](references/access.md).

## 2. Resolve the failure to a build and a job

Read the issue **including comments** — teammates often have already narrowed it down, and Analytics bots post newer occurrences as comments. Bot comments repeat full stacktraces, so extract the Run/Time pairs rather than reading everything (recipe in the reference).

There are two issue formats; details and recipes in [references/locating-the-failure.md](references/locating-the-failure.md):

- **Human-filed** (`### Build` section): the URL usually carries `?jid=`. That's the job.
- **Buildkite Analytics auto-filed** (`* **Test Name:**` bullets, `**Run:** https://api.buildkite.com/v2/analytics/...` links):
  1. For each Run URL, call `…/runs/<run-id>/failed_executions` and select the execution whose `test_name` ends with the failing test. `tags["build.url"]` is the exact build.
  2. **Ignore `tags["build.job_id"]`** — it is the "Aggregate test reports" job, not the one that ran the test.
  3. Find the real job: script jobs in the build with `state == "failed"` or `retried == true` (fetch with `?include_retried_jobs=true`), whose name fits the test's group/platform. Confirm by grepping the job log for `--- FAIL: <TestName>`.
- **No Run links at all** (the issue only has `Latest Occurrence`): scan Test Engine runs created in the few hours before that timestamp — see the reference.

**Artifacts expire after ~14 days**, but the Buildkite API keeps listing them. If the occurrence is older, check GCS before planning around it; if it's gone, look for a more recent failure of the same test (same reference, §"Finding other occurrences") and tell the user which occurrence you are analyzing.

With several occurrences, group them by (pipeline, branch, platform) and analyze the largest group; mention outliers in one line each unless they contradict your hypothesis.

Record: pipeline slug, build number, `build.id` and `pipeline.id` (UUIDs from the build JSON — needed for GCS paths), job id, job name, attempt (first run vs retry), full test name including subtests.

## 3. Fetch the job log and artifacts

- **Job log** — via the Buildkite API (`bk job log <job-id> -p <pipeline> -b <build>`, or `…/jobs/<job-id>/log.txt`). Save it to a file, strip the escape sequences ([references/artifacts.md](references/artifacts.md) §"Job log"), and grep it; don't read it whole. It shows VM image, setup steps, and failures that happen before any test artifact exists.
- **Artifacts** — list the job's objects in GCS, then download the test results and diagnostics (skip `build/distributions/**` if present — packages, large and irrelevant):
  ```bash
  P="gs://buildkite-elastic-agent/<pipeline.id>/<build.id>/<job-id>"
  gcloud storage ls -l "$P/**"                                     # what exists, with sizes
  mkdir -p "$RCA_DIR/build"
  gcloud storage cp "$P/build/*.xml" "$P/build/*.json" "$RCA_DIR/build/"
  gcloud storage cp -r "$P/build/diagnostics" "$RCA_DIR/build/"    # only if listed
  ```
  Use a scratch directory for `$RCA_DIR`. Quote every glob meant for the remote side or for a tool (`"gs://…/*.xml"`, `--include='*.go'`) — zsh fails on unmatched globs before the command runs. zsh also expands a word starting with `=` (`echo ====` fails), so quote those too. An empty listing for a job that uploaded artifacts means they expired.
- **Validate before trusting anything**: `file` on each download and `unzip -tq` on zips. An HTML file, or a size that differs from the listing, is not the artifact. See [references/artifacts.md](references/artifacts.md).

## 4. Read the test output → confirm the failure mode

- **JUnit XML** (`build/*.xml`) — the `<failure>` text of the failing `<testcase>`, i.e. the assertion.
- **gotestsum JSON** (`build/*.out.json`) — the full `t.Log` stream for the test, in order, with timestamps.
- **Job log** — everything outside the test binary.
- **Sibling tests in the same job** — did other tests fail at the same time with the same error? That points at the environment, not the test.

File naming and `jq`/Python recipes: [references/artifacts.md](references/artifacts.md) §"Reading test output"; test layout: [references/test-framework.md](references/test-framework.md).

## 5. Classify the failure surface — which management layer?

Now that you know the failing assertion, form a hypothesis about *which layer* the bug lives in and confirm it with the user.

**First, which runtime?** Not every component runs in the EDOT collector. Beat inputs run either as receivers in the collector (**otel**) or as separate beat subprocesses (**process**) — the migration to otel is ongoing, defaults differ by version, and some tests deliberately switch between the two. Elastic Endpoint (Elastic Defend) runs as an OS **service** with its own install/upgrade/uninstall lifecycle and its own logs. How to tell them apart, and each runtime's failure signatures: the diagnostics skill's [references/runtimes.md](../elastic-agent-diagnostics/references/runtimes.md). Without a bundle, the test name, group, and the policy it builds usually tell you.

For **otel** components the agent has **four management layers**, partitionable by log fields:

```
L1. elastic-agent supervisor (control plane)
    ↓ spawns / configures
L2. OTel collector core framework
    ↓ runs
L3. OTel pipeline components (receivers, processors, extensions)
    ↓ (for beat-based receivers) hosts
L4. embedded beat internals (filebeat, metricbeat, heartbeat, … code)
```

For **process** components the layers collapse to L1 ↔ the beat process (L4); for **Endpoint**, to L1 ↔ the Endpoint service.

Discrepancies between *adjacent* layers are some of the strongest signals — the supervisor told the collector to stop and the collector never logged shutting down; the collector started a receiver but the embedded beat never logged its startup; etc. See the diagnostics skill's playbook §"Discrepancy patterns to hunt" and §"Partitioning logs by management layer".

| Clue | Likely layer |
|---|---|
| Test asserts on agent state, fleet status, upgrade flow | **L1 supervisor** |
| Failure mentions coordinator, runtime manager, `internal/pkg/agent/` | **L1 supervisor** |
| Symptom is "config not applied", "collector stuck stopping" | **L1↔L2** boundary |
| Failure mentions `internal/pkg/otel/manager/`, `otelcol`, EDOT collector lifecycle | **L2 collector core** |
| Symptom is "receiver didn't start" / "receiver kept running after stop" | **L2↔L3** boundary |
| Failure mentions a specific receiver (`filebeatreceiver`, `metricbeatreceiver`), pipeline configuration | **L3 OTel component** |
| Symptom is beat-side input/output errors, registry corruption, harvester not picking up files | **L4 embedded beat** |
| Component stuck in `STOPPING` — like issue #14049 | **investigate L1↔L2 and L2↔L3 boundaries** |
| Missing DLL / shared library / driver / system package, on one platform only | **not a layer** — platform support or packaging; check `SkipOS` precedents in sibling tests |
| Fails on both attempts, every time, on one platform | deterministic platform problem, not a flake — compare with the platforms where it passes |
| Test name or subtest mentions `otel`/`process`/`compare`, or logs show `Deferring … until … instances stop` | **runtime switch** (L1) — the old instance must stop before the new one starts; check the transition, then each runtime separately |
| Endpoint / Elastic Defend / tamper protection / uninstall token; group `fleet-endpoint-security`; `endpoint` component | **L1 ↔ Endpoint service** — install/uninstall/upgrade lifecycle, check-ins, proxied actions; Endpoint's own log and diagnostics |
| A process-mode beat exits, or misses check-ins (`Failed: pid '…' exited with code …`) | **L1 ↔ beat process** |
| Agent healthy, but the test finds **0 documents** and the agent logs `events were dropped` / output errors | **not an agent layer** — the backing stack (Elasticsearch rejecting writes: shard limit, disk watermark, auth). Read `logs/*/events/` in the bundle for the status and reason; worked example: [examples/shared-stack-shard-limit.md](examples/shared-stack-shard-limit.md) |
| `Condition never satisfied` on a Fleet/Kibana-side gate (`IsPolicyRevision`, agent document, Fleet status) rather than on agent behaviour | **probably the test** — check the gate against the flake taxonomy (step 6e) before blaming the agent |

**Skip this step** when the failure is clearly outside the agent — e.g. the install command itself failed, the VM or package manager misbehaved, ESS/Fleet provisioning failed, or a runtime dependency is missing on the platform. Say so and go to step 6 with the no-bundle path.

Otherwise, **ask the user**: state your hypothesis (one sentence) and use `AskUserQuestion` with these options:

- **L1 — supervisor** — agent control plane only.
- **L2 — OTel collector core** — collector framework lifecycle, config delivery, shutdown sequence.
- **L3 — pipeline component** — a specific receiver / processor / extension.
- **L4 — beat** — beat code, embedded in a receiver or running as its own process.
- **Endpoint service** — Elastic Endpoint's lifecycle as driven by the agent, plus Endpoint's own log.
- **All / unknown** — partition all layers, hunt cross-layer discrepancies. Default for ambiguous symptoms.
- **Not the agent** — the environment (backing stack, CI host, package manager) or the test itself. Use when the evidence already shows the agent behaved correctly.

`AskUserQuestion` takes at most four options: offer the three most plausible layers for the runtimes involved (no L2/L3 for a process-mode beat; Endpoint service only when Endpoint is installed) plus **All / unknown**.

Capture the choice as `$RCA_LAYERS` ∈ `{L1, L2, L3, L4, endpoint, all}`. If the user picks a single layer but a cross-layer discrepancy turns out to be the more likely explanation, surface that and ask whether to broaden. If you can't ask (e.g. you are running as a subagent), state the hypothesis and use `all`.

## 6. Analyze

### 6a. Diagnostics bundle → invoke the diagnostics skill

Bundles are `build/diagnostics/<TestName with / → ->-<RFC3339 with : → ->-diagnostics.zip`. If several match, pick the one closest to the JUnit failure timestamp; tests with two agents (e.g. fleet-server + agent under test) legitimately produce two.

Hand the bundle to the `elastic-agent-diagnostics` skill via the Skill tool:

> Skill: elastic-agent-diagnostics
> args: Apply the skill to the bundle at <path>.zip. Produce the full triage summary.

**Don't duplicate its work** — use its triage as primary evidence.

**No bundle?** That's expected when the test failed before the agent was installed, or before the fixture collected diagnostics — it is not a sign the URL is wrong. Work from the job log, the test output, sibling-test failures in the same job, and the test fixture code (`pkg/testing/`) instead.

### 6b. Per-layer log analysis

Partition the bundle's logs by layer and check each against its own expected behaviour, scoped by `$RCA_LAYERS`. The diagnostics skill's playbook §"Partitioning logs by management layer" has the classification `jq`; the per-component checklist and discrepancy table are in [references/rca-playbook.md](references/rca-playbook.md).

For every component id in `state.yaml` *or* the logs, note its runtime, then:
1. **L1**: did the supervisor start/stop/remove it, and log the state transitions?
2. **L3** (otel only): did the receiver log its own startup and shutdown?
3. **L4**: did the beat reach `Beat ID:` / `Home path:`? Did it log its own shutdown? For a process-mode beat, did the process exit, and with what code?
4. **Endpoint** (service only): did install/verify succeed, did it check in, and on removal did `uninstall endpoint service` reach `Stopped: endpoint service runtime`? What does Endpoint's own log say at the same moment?
5. **Cross-layer**: for each transition the supervisor logged, does the next layer react within seconds? (Endpoint's check-in period is 30 s and its timeouts are 600 s, so allow for that.)

When you find a discrepancy between adjacent layers, that pattern plus the log-line citations *is* the evidence chain.

### 6c. Test source → understand intent

The job name and the JUnit file name tell you the test group (see [references/test-framework.md](references/test-framework.md)); the Go package in the Test Engine `test_name` tells you the directory. Find the test with `grep -rn "func <TestName>" testing/integration/`.

**Read the code the build actually ran.** Take `commit` and `branch` from the build JSON; release branches (`9.5`, `8.19`, …) can differ substantially from your checkout. Use `git show "${commit}:<path>"` (after `git fetch origin <branch>` if the commit isn't local — that only updates remote-tracking refs, which is fine) rather than reading `HEAD` — in zsh, write `${commit}:` with braces, or `:t…` after a bare `$commit` is parsed as a modifier.

Read the test top-to-bottom: setup (policy, integration, install args), the failing assertion (match it to the JUnit message), timing assumptions (`Eventually`, `Wait`, sleep durations).

### 6d. Implementation source → trace the failure surface

Read the code the evidence points at — the diagnostics triage, the failing fixture call, or the component whose logs diverged. If the failure is "X is still present after removal", trace the removal codepath.

### 6e. History → is it new, and what changed?

- **Known flake patterns**: the `integration-test-review` skill's [flake taxonomy](../integration-test-review/references/flake-taxonomy.md) lists the anti-patterns behind past flakes with the fixing commits (e.g. exact `IsPolicyRevision` equality on a shared stack, #14911). A match there is strong evidence for a test bug, and the cited fix is the template.
- **Git**: `git log --since='6 weeks ago' --oneline -- <files>` for the test file and the implicated source; `git log --grep='<keyword>'`; `git log -S '<identifier>'` to find when a helper or fix was introduced.
- **CI**: is this failure chronic or new? Which branches, platforms, VM images? Does it fail on first attempt and pass on retry? See [references/locating-the-failure.md](references/locating-the-failure.md) §"Finding other occurrences". Cross-reference dates with the issue's occurrences and with commits.

## 7. Produce the RCA report

Structure (details in [references/rca-playbook.md](references/rca-playbook.md)):
- **Failure mode** — one sentence: what assertion failed and the symptom.
- **Evidence chain** — bullets, each citing a file + finding: `state.yaml: filestream-monitoring state=5 (STOPPING)`, `logs/…/elastic-agent-20260506.ndjson:42: timeout waiting for collector to stop`, `job log 15:28:34: rpm lock contention`.
- **Suspected cause** — agent bug vs test bug vs infra/environment, and why.
- **Confidence** — high / medium / low, and what would raise it.
- **Next investigation step** — one concrete action. Stop here — do not propose code changes.

Cite the Buildkite build and job URLs, the issue, source files (`<file>:<line>`), and bundle paths so the user can click through. Mention which occurrence you analyzed if it isn't the one in the issue.

## Example

[examples/shared-stack-shard-limit.md](examples/shared-stack-shard-limit.md) walks a complete RCA (an auto-filed issue where the agent was healthy and the shared Elasticsearch stack rejected writes): the report, the commands that produced each piece of evidence, and the pitfalls on the way. Read it once to calibrate the depth and format expected.

## House rules

- **Validate every download.** A file with the right name is not the right file until it parses.
- **Never invent build numbers, job IDs, or artifact paths.** If an artifact is missing, say so and explain the likely reason (expired, never uploaded, failure before upload).
- **"Listed" ≠ available.** The Buildkite API lists artifacts whose GCS objects have expired.
- **Say what was proven and what was inferred.** If you opened two bundles out of ten affected jobs, the report says so.
- **Don't re-implement the diagnostics skill's triage.** Invoke it; cite its findings.
- **Distinguish test flakiness from agent bugs from infra.** A timing-sensitive `Eventually` with too-short timeout is a test bug. A consistent state-machine deadlock is an agent bug. A package-manager lock or cloud quota error is infra. Say which you think it is.
- **Stop at root cause + next step.** Do not write code or open PRs. The user will follow up if they want a fix.
