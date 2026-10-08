# Locating the failure: issue → build → job

Commands below use `bk`; the `curl` + `BUILDKITE_API_TOKEN` and MCP equivalents are in [access.md](access.md). Save responses to files and filter with `jq`.

## Issue formats

### A — human-filed

Filed from the `.github/ISSUE_TEMPLATE/flaky-test.yml` form; the sections below are its fields.

Title: `[Flaky Test]:TestFunctionName – <short error>` or `[Flaky Test] TestName/SubTest on <OS>`. Body sections (`###` headings):

| Section | Contents |
|---|---|
| `### Failing test case` | Go test name, subtests `/`-separated — use verbatim |
| `### Error message` | top-level failure, no stacktrace — often identifies the class (timeout, version conflict, nil pointer) |
| `### Build` | a Buildkite job URL: `https://buildkite.com/elastic/<slug>/builds/<n>/<canvas\|table\|waterfall>?jid=<job-uuid>&tab=output#L1153` — ignore `&tab=` and `#L…` |
| `### OS` | platform(s) where it was seen, possibly several |
| `### Stacktrace and notes` | fenced test output. **Often the smoking gun** — reporters paste the telling log line, and the diagnostics bundle file name (e.g. `…diagnostics\TestFleetDownloadProxyURL-2026-05-06T17-33-50Z-diagnostics.zip`) |

### B — Buildkite Analytics auto-filed

Title: `[Flaky Test] github.com/elastic/elastic-agent/testing/integration/<pkg> TestName[/subtest]`. Body:

```markdown
* **Test Name:** TestFleetManagedUpgradeRollback
* **Scope:** github.com/elastic/elastic-agent/testing/integration/ess
* **Buildkite Link:** https://buildkite.com/organizations/elastic/analytics/suites/elastic-agent-ci/tests/<test-uuid>
* **Flaky Instances:** 2
* **Latest Occurrence:** 2026-08-04T19:24:59.133Z
### Details            ← JSON with the same fields
### Failure Examples   ← optional
**Run:** https://api.buildkite.com/v2/analytics/organizations/elastic/suites/elastic-agent-ci/runs/<run-uuid>
**Time:** …
**Stacktrace:**        ← usually empty or uninformative
```

New occurrences arrive as `## Flaky Test Still Occurring` bot comments, each with its own `**Run:**`/`**Time:**` — the newest Run is usually in the last comment, and each comment shows only one example even when more exist (use the "No Run links" scan below for a complete list). Bots repeat full stacktraces, so the whole issue can be hundreds of KB; pull just the occurrences:

```bash
gh issue view <N> -R elastic/elastic-agent --json body,comments --jq '.body, .comments[].body' \
  | grep -oE '\*\*(Run|Time):\*\* *[^ ]+' | sed -E 's/\*\*(Run|Time):\*\* *//' | paste - - | sort -k2
```

Often a single failure is filed as several issues — one for the parent test and one per failing subtest. Check the neighbouring issue numbers; they usually share a root cause.

## Analytics Run → build

```bash
RUN=<run-uuid>                       # last segment of the **Run:** URL
TEST='TestRpmFleetUpgrade'           # as in **Test Name:**, subtests included
bk api --analytics "/suites/elastic-agent-ci/runs/$RUN/failed_executions?per_page=100" 2>/dev/null > fe.json
jq -r --arg t "$TEST" '.[] | select(.test_name | endswith(" " + $t))
  | "\(.created_at)  \(.tags["build.url"])  aggregator_job=\(.tags["build.job_id"])"' fe.json
```

- `test_name` is `"<go package> <TestName[/subtest]>"`.
- `tags["build.url"]` is the exact build. **`tags["build.job_id"]` is the "Aggregate test reports" job** (it uploads results to Test Engine; it has no test artifacts) — don't use it as the job.
- The run JSON itself (`…/runs/<run-uuid>`) also has `build_id` (the build UUID) and `commit_sha`, but no build number.
- `failed_executions` returns many rows per run (duplicates with different `created_at`): reduce with `| sort -u`. Auto-filed issues often list several Examples but carry one Run; dedupe the Run URLs before looping.
- Process every Run link, not just the first: different examples are often different builds, branches or platforms, and some may have expired.
- `created_at` on a failed execution is when results were uploaded (after the job ends), not when the test failed. Match the issue's `**Time:**` against job `started_at`/`finished_at`.
- `tags` carry no OS/arch/branch. Get the platform from the job name, or from package names in the stacktrace (e.g. `elastic-agent-<v>-windows-arm64.zip`).

## No Run links

When the issue has only `Latest Occurrence`, scan recent runs. Flaky runs often *passed* overall (the retry passed), so don't filter on `result`:

```bash
LATEST='2026-09-28T17:35:41Z'; FROM='2026-09-28T13:00:00Z'   # ~3–4 h before; runs start long before a test fails
TEST='TestRpmLogIngestFleetManaged'
bk api --analytics "/suites/elastic-agent-ci/runs?per_page=100" 2>/dev/null > runs.json   # page=2,3… to go further back (~1 day per page)
jq -r --arg f "$FROM" --arg l "$LATEST" '.[] | select(.created_at >= $f and .created_at <= $l) | .id' runs.json |
while read -r run; do
  bk api --analytics "/suites/elastic-agent-ci/runs/$run/failed_executions?per_page=100" 2>/dev/null |
    jq -r --arg t "$TEST" '.[] | select(.test_name | endswith(" " + $t)) | "\(.created_at)  \(.tags["build.url"])"'
done
```

There is no per-test executions endpoint (`…/tests/<id>/executions` → 404).

## Build → job

```bash
bk api "/pipelines/<slug>/builds/<n>?include_retried_jobs=true" 2>/dev/null > build.json
jq -r '.pipeline.id, .id' build.json            # UUIDs for the GCS path
jq -r '.jobs[] | select(.type=="script" and (.state=="failed" or .retried==true))
  | "\(.id)  \(.state)  retried=\(.retried)  \(.started_at)  \(.name)"' build.json
```

- Job names encode OS, arch, sudo flag, test group and VM image — e.g. `linux:amd64:tier3:true:rpm:platform-ingest-elastic-agent-rhel-8-1789434098` (group `rpm`, sudo) or `:kubernetes:tier2:v1.27.16:amd64:slim`. The test's group is declared in its `define.Require(... Group: integration.<X>)`; values live in `testing/integration/groups.go`.
- For a flaky test, the failing attempt is usually the job with `retried == true`; the retry is a new job id that may have passed. Match the occurrence time against `started_at`/`finished_at` when several candidates remain.
- **Confirm** before downloading anything. gotestsum prints either `--- FAIL: <Test> (…)` or, in its summary, `=== FAIL: <pkg> <Test> (…)`:
  ```bash
  bk job log <job-id> -p <slug> -b <n> 2>/dev/null | perl -pe 's/\e_(bk;t=\d+\a)?//g; s/\e\[[0-9;]*[A-Za-z]//g' > job.log
  grep -aE -- "FAIL:( [^ ]+)? $TEST \(" job.log; grep -aE 'DONE [0-9]+ tests' job.log
  ```
- In a large build (~50+ failed or retried jobs) don't guess: fetch each candidate's log and count which contain `--- FAIL: <Test>` (loop in the worked example). The first attempt is not always the interesting one — retries can fail where first attempts passed, which points at stack state that changed during the build.
- **If the retry failed the same way too**, the test probably fails every time on that platform. That is a strong classification clue: look for a platform-specific cause before timing or flakiness.

## Finding other occurrences

Use this both when the issue's occurrences have expired and to answer "is this new or chronic?" in step 6e.

- **GitHub** — earlier issues for the same test, including closed ones, often carry the prior RCA: `gh issue list -R elastic/elastic-agent --search '"<TestName>" in:title' --state all`.
- **Test Engine** — the "No Run links" scan over a wider window (more `page=`s) lists every build where the test failed and reported.
- **Buildkite builds** — for failures that never reach Test Engine (e.g. whole-job failures), list builds and filter jobs by name and state:
  ```bash
  bk api "/pipelines/elastic-agent-extended-testing/builds?branch=main&created_from=2026-09-01T00:00:00Z&include_retried_jobs=true&per_page=100" 2>/dev/null > builds.json
  jq -r '.[] | .number as $n | .jobs[] | select((.name // "") | test("rhel-8")) | select(.type=="script")
    | "\($n)  \(.started_at[:10])  \(.state)  retried=\(.retried)  \(.id)"' builds.json
  ```
  Then grep the job logs (or GCS JUnit, within retention) for the failing test.

**Prioritize.** Group occurrences by (pipeline, branch, platform). Analyze the largest group in depth; give each outlier one line in the report unless it contradicts your hypothesis — then it deserves a look.

Summarize as: failing first attempts vs retries, per branch, per platform/image, since when. That distinguishes "new regression" (look at commits) from "chronic flake" (look at the environment or the test).
