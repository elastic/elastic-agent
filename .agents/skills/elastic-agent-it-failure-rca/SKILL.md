---
name: elastic-agent-it-failure-rca
description: Root-cause an elastic-agent integration test failure. Use when the user provides a flaky-test issue from elastic/elastic-agent (e.g. "look at #14049"), a Buildkite build URL with a job UUID, or a local artifacts directory, and wants a structured RCA report.
---

# Elastic Agent integration-test failure RCA

End-to-end root-cause analysis for an elastic-agent integration test failure. Pulls artifacts from Buildkite, hands the diagnostics bundle to `elastic-agent-diagnostics`, reads the test source and recent history, and produces a structured RCA report.

## Inputs accepted

One of:
1. **GitHub issue reference** — `#14049`, `elastic/elastic-agent#14049`, or full URL. **Preferred** — the issue carries the test name + build URL + OS in the standard `[Flaky Test]` template.
2. **Buildkite build URL with job UUID** — `https://buildkite.com/elastic/elastic-agent/builds/38654/table?jid=<uuid>`. Use when there is no issue yet.
3. **Local artifacts directory** — if the user already downloaded artifacts (or has a diagnostics zip), skip to step 5.

If unclear, ask which of the three the user has.

## Use the helper scripts as the primary tools

This skill ships `bin/itrca` and pairs with the diagnostics skill's `bin/diag`. **Prefer them over raw `gh`/`bk`/`curl`/`jq`** — each call is a single named binary, so one approval covers all uses of that subcommand.

**Path requirement.** Always invoke each helper with its **absolute path**. Construct the paths from each skill's base directory — the absolute path printed when the Skill tool launched the skill (look for `Base directory for this skill: <abs-path>`). Assigning the absolute path to a variable for re-use is fine; **do not** use `~` (the permission parser can't statically resolve tilde, which forces a prompt).

For brevity below, `<ITRCA>` = `<this-skill-base-dir>/bin/itrca` and `<DIAG>` = `<diagnostics-skill-base-dir>/bin/diag`.

```bash
<ITRCA> authcheck                                  # verify auth
<ITRCA> issue <number>                             # parse a flaky-test issue
<ITRCA> parse-build-url <url>                      # pipeline/build/jid
<ITRCA> download <org/pipeline> <build> <jid>      # fetch artifacts
<ITRCA> match <rca-dir> <test-name>                # find diagnostics zips
<ITRCA> junit <rca-dir>                            # failed test cases
<ITRCA> testlog <rca-dir> <test-name>              # gotestsum output
<DIAG>  triage <bundle>                            # bundle triage
<DIAG>  layers <bundle> [<component>]              # cross-layer logs
# ...see `<DIAG> help` and `<ITRCA> help` for more
```

Drop to raw shell commands only when the question is genuinely ad-hoc and no subcommand fits.

## Workflow

### 1. Verify auth, fail fast

Run `<ITRCA> authcheck`. It enforces:

- `gh` is installed and `gh api user` returns the authenticated user (the actual API probe — `gh auth status` is unreliable when stale accounts are configured alongside a working `GH_TOKEN`).
- Either `bk` is authenticated, or `BUILDKITE_API_TOKEN` is set in the environment.

```bash
<ITRCA> authcheck
```

If it aborts, **stop and report exactly what the error message says**. Do not search the filesystem, env, dotfiles, or keychains for credentials — the script's checks are the complete list of acceptable sources.

Common remediations:
- `gh` not installed → "Install GitHub CLI: https://cli.github.com/"
- `gh api user` failed → "Run `! gh auth login -h github.com`, then ask me to retry."
- No Buildkite auth → "Either run `! bk auth login`, or set `BUILDKITE_API_TOKEN` (from https://buildkite.com/user/api-access-tokens). The token needs the `read_artifacts` scope."

The `!` prefix tells Claude Code to run the command in the user's session — required for the interactive OAuth/device-code flows of `gh auth login` and `bk auth login`.

### 2. Parse the input

For an issue:

```bash
<ITRCA> issue <number-or-url>
```

That prints test name, build URL, build/jid, OS, and any inline notes from the "Stacktrace and notes" section. Format details in [references/issue-format.md](references/issue-format.md).

For a bare build URL:

```bash
<ITRCA> parse-build-url <url>
```

**Inline state.yaml / log fragments in the issue are often the smoking gun the reporter already noticed** — read them carefully before downloading anything.

### 3. Classify the failure surface — which management layer?

Before downloading artifacts, form a hypothesis about *which layer* the bug lives in and confirm it with the user. The agent has up to **four management layers** that log to the same NDJSON file but are partition-able by tag fields:

```
L1. elastic-agent supervisor (control plane)
    ↓ spawns / configures
L2. OTel collector core framework
    ↓ runs
L3. OTel pipeline components (receivers, processors, extensions)
    ↓ (for beat-based receivers) hosts
L4. embedded beat internals (filebeat, metricbeat code)
```

Discrepancies between *adjacent* layers are some of the strongest signals — supervisor told the collector to stop and the collector never logged shutting down; collector started a receiver but the embedded beat never logged its startup; etc. See the diagnostics skill's playbook §"Discrepancy patterns to hunt" for the canonical list and the §"Partitioning logs by management layer" filter rules.

**Form a hypothesis from what you already know:**

| Clue | Likely layer |
|---|---|
| Test asserts on agent state, fleet status, upgrade flow | **L1 supervisor** |
| Inline notes mention coordinator, runtime manager, `internal/pkg/agent/` | **L1 supervisor** |
| Symptom is "config not applied", "collector stuck stopping" | **L1↔L2** boundary |
| Inline notes mention `internal/pkg/otel/manager/`, `otelcol`, EDOT collector lifecycle | **L2 collector core** |
| Symptom is "receiver didn't start" / "receiver kept running after stop" | **L2↔L3** boundary |
| Inline notes mention specific receiver (`filebeatreceiver`, `metricbeatreceiver`), pipeline configuration | **L3 OTel component** |
| Symptom is "beat-side input/output errors", registry corruption, harvester not picking up files | **L4 embedded beat** |
| Component stuck in `STOPPING` — like issue #14049 | **investigate L1↔L2 and L2↔L3 boundaries** |

**Ask the user.** State your hypothesis (one sentence) and use `AskUserQuestion` with these options:

- **L1 — supervisor** — agent control plane only.
- **L2 — OTel collector core** — collector framework lifecycle, config delivery, shutdown sequence.
- **L3 — pipeline component** — a specific receiver / processor / extension.
- **L4 — embedded beat** — filebeat / metricbeat code running inside a receiver.
- **All / unknown** — partition all layers, hunt cross-layer discrepancies. Default for ambiguous symptoms.

**Capture the choice** as `$RCA_LAYERS` ∈ `{L1, L2, L3, L4, all}`. Step 6 uses it to scope log slicing and source reading order. If the user picks a single layer but cross-layer discrepancy turns out to be the more likely explanation, surface that and ask whether to broaden.

### 4. Download artifacts

```bash
<ITRCA> download <org/pipeline> <build> <jid>
```

This filters to JUnit XMLs (`build/*.integration.xml`), gotestsum JSON (`build/*.integration.out.json`), diagnostics zips (`build/diagnostics/*.zip`), and `build/TEST-report.html`, and writes them under `$TMPDIR/it-rca/<build>-<jid>/build/...` preserving the artifact paths.

Capture the destination as `$RCA_DIR` for later steps. The script prints it on the last line of output.

Implementation notes (in [references/buildkite-artifacts.md](references/buildkite-artifacts.md)):
- Prefers the REST API when `BUILDKITE_API_TOKEN` is set (the `bk` download path needs GraphQL scope which most read-only tokens don't have).
- The pipeline-slug is parsed from the URL — usually `elastic/elastic-agent` for PR-triggered runs, `elastic/elastic-agent-extended-testing` for the IT matrix.

### 5. Map the failing test to its diagnostics

```bash
<ITRCA> match "$RCA_DIR" "<full-test-name-with-subtest>"
```

Sanitization (test-name `/` → `-`) and matching are done by the script. If multiple bundles match, pick the one with timestamp closest to the failure timestamp from the JUnit XML. Per-file naming details in [references/test-framework.md](references/test-framework.md).

### 6. Analyze, layer by layer

#### 6a. Test report → confirm the failure mode

```bash
<ITRCA> junit "$RCA_DIR"                             # all failed test cases with first 25 lines of stack
<ITRCA> testlog "$RCA_DIR" "<full-test-name>"        # gotestsum stdout/stderr for one test
```

The JUnit `<failure>` text gives you the assertion message; the gotestsum stream gives `t.Log` output and the printed stacktrace. Both are usually needed.

#### 6b. Diagnostics bundle → invoke the diagnostics skill

Hand the bundle path to the `elastic-agent-diagnostics` skill via the Skill tool:

> Skill: elastic-agent-diagnostics
> args: Apply the skill to the bundle at $RCA_DIR/build/diagnostics/<file>.zip. Produce the full triage summary.

That skill leads with `<DIAG> triage` (and other `<DIAG>` subcommands) so the actual analysis runs as named-binary invocations. **Do not duplicate its work** — let it produce the structured triage and use the result as primary evidence.

#### 6c. Per-layer log analysis — verify each layer independently and hunt cross-layer discrepancies

The diagnostics skill produces an overall triage. This step **partitions the logs by management layer** so each can be checked against its own expected behavior, and so cross-layer discrepancies surface. Drive scope from `$RCA_LAYERS` set in step 3:

| `$RCA_LAYERS` | What to slice and check |
|---|---|
| `L1` | `<DIAG> layer <bundle> L1 [<component>]` — supervisor only |
| `L2` | `<DIAG> layer <bundle> L2 [<component>]` — collector core only |
| `L3` | `<DIAG> layer <bundle> L3 [<component>]` — pipeline component (receiver/processor/extension) |
| `L4` | `<DIAG> layer <bundle> L4 [<component>]` — embedded beat |
| `all` | `<DIAG> layers <bundle> [<component>]` — cross-layer interleaved with `L1/L2/L3/L4` tags. **Default for ambiguous symptoms.** |

**Per-component layer-by-layer health check.** For every component-id seen in state.yaml *or* the logs:

1. **L1 view of the component:** did the supervisor try to start/stop/remove it? Were the state transitions logged?
2. **L3 view (receiver shell):** did the receiver log its own startup and shutdown for that component-id?
3. **L4 view (embedded beat, if applicable):** did the beat get to "Beat ID:" / "Home path:" startup? Did it log its own shutdown?
4. **Cross-layer:** for each transition the supervisor logged, does the next layer down show the corresponding reaction within seconds?

The full per-component verification queries — including the cross-layer interleaved timeline — live in [references/rca-playbook.md](references/rca-playbook.md) §"Per-component log verification". The canonical layer filters are in the diagnostics skill's playbook §"Partitioning logs by management layer".

**Discrepancies between adjacent layers are often the smoking gun:**

- L1 says "Stopping component" → L2 never logs `Starting shutdown...` → supervisor failed to deliver the signal.
- L2 logs `Starting shutdown...` → L3 receiver keeps logging activity → receiver ignored shutdown.
- L3 receiver shell configured → L4 embedded beat never logged `Beat ID:` → receiver bridge broken.
- L4 beat logs clean shutdown → L1 still shows component in `STOPPING` state → supervisor state-propagation bug.

When you find such a discrepancy, that pattern + line citations *are* the evidence chain. Copy them straight into the report.

#### 6d. Test source → understand intent

The test framework's group name (from the artifact filename) tells you which test directory. For `fleet-endpoint-security`, the test lives under `testing/integration/ess/`. Find the test:

```bash
grep -rn "func <test-name>" testing/integration/ pkg/testing/
```

Read the test top-to-bottom. Note:
- What it sets up (policy, integration, agent install args).
- Where the failing assertion is — match it against the JUnit failure message.
- Timing assumptions (`Eventually`, `Wait`, sleep durations).

#### 6e. Implementation source → trace the failure surface

The diagnostics skill will have pointed at specific Go files (e.g. `internal/pkg/otel/manager/`). Read those. If the failure is "X is still present after removal", trace the removal codepath.

#### 6f. Recent history → find the suspect commit

```bash
# Files the diagnostics skill flagged + the test file itself
git log --since='6 weeks ago' --oneline -- <files>
git log --since='6 weeks ago' --grep='<keyword>' --oneline
```

Cross-reference dates with the issue's "Failed runs" table if present.

### 7. Produce the RCA report

Use the structure in [references/rca-playbook.md](references/rca-playbook.md):
- **Failure mode** — one sentence stating what assertion failed and the symptom.
- **Evidence chain** — bullet list, each citing a file path + finding (`state.yaml: filestream-monitoring state=5 (STOPPING)`, `logs/...20260506.ndjson:42: timeout waiting for collector to stop`, etc).
- **Suspected cause** — your best hypothesis, distinguishing test bug vs agent bug vs infra/environment.
- **Confidence** — high / medium / low, with what would raise it.
- **Next investigation step** — one concrete action (read X, reproduce locally with Y, check git log for Z). Stop here — do not propose code changes.

Cite buildkite job, issue, source files, and bundle paths the same way you'd cite source code: `<file>:<line>` so the user can click through.

## House rules

- **Never invent build numbers, job IDs, or artifact paths.** If `bk artifacts list` returns nothing matching, say so and ask the user to verify the URL — don't synthesize an answer.
- **Don't re-implement the diagnostics skill's triage.** Invoke it; cite its findings.
- **Distinguish test flakiness from agent bugs.** A timing-sensitive `Eventually` with too-short timeout is a test bug. A consistent state-machine deadlock is an agent bug. Say which you think it is.
- **Multiple bundles per failure are normal.** A test with two agents (e.g. fleet-server + agent) produces two bundles. Match by sanitized test-name prefix and timestamp.
- **Stop at root-cause + next step.** Do not write code or open PRs. The user will follow up explicitly if they want a fix.
