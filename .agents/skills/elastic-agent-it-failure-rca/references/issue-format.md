# Flaky Test Issue Format

There are two distinct issue formats in elastic/elastic-agent. The `itrca issue` command handles both automatically.

---

## Format A — Manual template (human-filed)

Titles:
```
[Flaky Test]:TestFunctionName – <short error description>
[Flaky Test] TestName/SubTest on <OS>
```

Examples:
- `[Flaky Test]:TestFleetDownloadProxyURL – unable to upgrade agent with ID [...]: version_conflict_engine_exception`
- `[Flaky Test]:TestUpgradeFleetManagedElasticAgent – context deadline exceeded`

### Body sections

The body uses `###` headings. Sections appear in this order:

### `### Failing test case`

The Go test function name, optionally with subtests separated by `/`.

```
TestFleetDownloadProxyURL
TestNetworkTraffic/TestBeatsMetrics/otel
```

This is the canonical test name — use it verbatim for `<ITRCA> match` and `<ITRCA> testlog`.

### `### Error message`

The top-level assertion failure or error string, without the full stacktrace. Useful for quick triage before downloading artifacts — it often identifies the failure class directly (version conflict, timeout, nil pointer, etc.).

### `### Build`

A single Buildkite job URL. The URL typically includes `?jid=<uuid>` identifying the specific job, plus optional view/anchor noise (`&tab=output#L1153`) that should be ignored.

```
https://buildkite.com/elastic/elastic-agent/builds/38703/canvas?jid=019dfe2c-b189-49a7-bfd8-8890845930e3&tab=output#L1153
```

The `itrca issue` command strips the `&tab=` and `#L<n>` suffixes automatically.

### `### OS`

Platform string(s) on which the failure was observed. May list multiple:

```
Linux, Windows
ubuntu/amd64
windows/amd64
```

### `### Stacktrace and notes`

A fenced code block (usually tagged ` ```markdown `) containing the full Go test output: `t.Log`/`t.Logf` lines, the assertion failure with `Error Trace` / `Error` / `Test` fields, and any post-failure fixture cleanup output.

**This section is often the smoking gun.** Read it before downloading any artifacts — reporters frequently paste the exact log line that reveals the root cause, and inline diagnostics paths point directly to the failing bundle filename (e.g. `TestFleetDownloadProxyURL-2026-05-06T17-33-50Z-diagnostics.zip`).

---

## Format B — Buildkite Analytics auto-generated

Filed automatically by the Buildkite Analytics flaky-test detector. Title:
```
[Flaky Test] github.com/elastic/elastic-agent/testing/integration/<group> TestFunctionName
```

Example: `[Flaky Test] github.com/elastic/elastic-agent/testing/integration/ess TestFleetManagedUpgradeRollback`

### Body structure

```markdown
## Flaky Test

* **Test Name:** TestFleetManagedUpgradeRollback
* **Scope:** github.com/elastic/elastic-agent/testing/integration/ess
* **File:** N/A
* **Location:** N/A
* **Buildkite Link:** https://buildkite.com/organizations/elastic/analytics/suites/elastic-agent-ci/tests/<test-uuid>
* **Flaky Instances:** 1
* **Latest Occurrence:** 2026-08-04T19:24:59.133Z

### Details
```json
{ "id": "...", "name": "TestFleetManagedUpgradeRollback", ... }
```

### Failure Examples

**Example 1:**
**Run:** https://api.buildkite.com/v2/analytics/organizations/elastic/suites/elastic-agent-ci/runs/<run-uuid>
**Time:** 2026-08-04T17:27:12.766Z
**Stacktrace:**

```
=== RUN   TestFleetManagedUpgradeRollback
    ...
--- FAIL: TestFleetManagedUpgradeRollback (120.11s)
```
```

Key differences from the manual template:
- **No `### Build` section** — the Buildkite Link is an Analytics suite URL, not a build job URL.
- **`**Run:** <api-url>`** in Failure Examples is the actual run reference. `itrca issue` calls the Analytics API for this URL to resolve commit SHA and branch, then searches for the matching Buildkite build.
- **`**Stacktrace:**`** block (under Failure Examples) replaces `### Stacktrace and notes`.
- **`scope:`** output field is added for the Go package path.
- **`jid:` will be empty** — use `<ITRCA> parse-build-url <build_url>` to list jobs and pick the right one.

### Resolving a run URL manually

```bash
<ITRCA> analytics-run https://api.buildkite.com/v2/analytics/organizations/elastic/suites/elastic-agent-ci/runs/<id>
# → https://buildkite.com/elastic/elastic-agent/builds/44207
```

---

## Parsing with itrca

```bash
<ITRCA> issue <number>
# or
<ITRCA> issue https://github.com/elastic/elastic-agent/issues/<number>
```

Output fields for format A (full):
```
test_name: TestFleetDownloadProxyURL
build_url: https://buildkite.com/elastic/elastic-agent/builds/38703/canvas?jid=019dfe2c-b189-49a7-bfd8-8890845930e3
build:     38703
pipeline:  elastic/elastic-agent
jid:       019dfe2c-b189-49a7-bfd8-8890845930e3
os:        Linux, Windows
notes:
  proxy_url_test.go:936: Agent ID: "..."
  ...
```

Output fields for format B (analytics):
```
test_name: TestFleetManagedUpgradeRollback
scope:     github.com/elastic/elastic-agent/testing/integration/ess
build_url: https://buildkite.com/elastic/elastic-agent/builds/44207
build:     44207
pipeline:  elastic/elastic-agent
jid:       
os:        
notes:
  === RUN   TestFleetManagedUpgradeRollback
  ...
```

If `jid` is blank, the build URL had no `?jid=` parameter — use `<ITRCA> parse-build-url` next.

## Common pitfalls

- **Build URL view type varies**: the path segment before `?jid=` can be `canvas`, `table`, or `waterfall` — all are valid and parse identically.
- **`&tab=output#L1153` suffix**: anchor and tab params are UI state, not part of the artifact URL. `itrca issue` strips them; strip manually if working with the URL directly.
- **Test name has subtests**: the full name including subtests (`TestNetworkTraffic/TestBeatsMetrics/otel`) is needed for `<ITRCA> match` — the diagnostics zip filename is derived from it with `/` replaced by `-`.
- **PR builds vs IT matrix builds**: PR builds use pipeline `elastic/elastic-agent`; scheduled IT matrix runs use `elastic/elastic-agent-extended-testing`. The artifact layout is identical but the pipeline slug differs, which matters for `<ITRCA> download`.
- **Diagnostics path in notes**: the stacktrace section often contains the exact diagnostics filename (e.g. `fixture_install.go:820: >> running binary with: [...diagnostics\TestFleetDownloadProxyURL-2026-05-06T17-33-50Z-diagnostics.zip]`). Extract it directly rather than running `<ITRCA> match` when it's present.
- **Analytics format — `jid` is always empty**: `itrca issue` can resolve the build number but cannot determine which specific job within that build ran the test. Run `<ITRCA> parse-build-url <build_url>` to list all jobs; pick the one matching the test group (e.g. an ESS integration test job for scope `testing/integration/ess`).
