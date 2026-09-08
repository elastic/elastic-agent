---
name: integration-test-review
description: Review elastic-agent integration test changes (testing/integration/**) for flakiness risks before merge. Use when reviewing a PR, diff, or commit that adds or modifies integration tests, or when asked whether an integration test will be stable in CI.
---

# Integration test flakiness review

Integration tests in this repo run on real VMs against live ESS stacks, on hosts that
vary in speed, distro, kernel, and concurrent load. The dominant failure mode is a test
that passes locally and in the PR run, then flakes weeks later on a slower host, a
different distro, or after an unrelated product change. This skill encodes the failure
modes actually observed in a year of flake fixes (see
[references/flake-taxonomy.md](references/flake-taxonomy.md) for the evidence: every
rule below cites real incidents).

## Method

1. Read the diff. For each **added or modified test function**, also read enough
   surrounding file context to understand the test's setup, assertions, and cleanup —
   flakes usually live in the interaction, not the changed lines alone.
2. Run the Tier 1 mechanical scan over the changed files.
3. For each test, walk the Tier 2 semantic questions that match what the test does.
4. Check Tier 3 idioms: is the test hand-rolling something a shared helper does safely?
5. Report findings: `file:line`, category, why it will flake (concrete scenario on a
   slow/parallel/different-OS host), and the fix. Rank by likelihood × blast radius.
   A test that can leave an installed agent, a root-owned dir, or a mutated shared
   Fleet object behind poisons *other* tests — rank that above a self-contained flake.

Judge only realistic nondeterminism. Do not flag a wait as "racy" if the condition is
polled with a generous budget; do flag budgets with no headroom over known product
intervals (see Tier 2 §Timeouts).

## Tier 1 — mechanical red flags (grep the diff first)

Each of these has caused real CI failures; they are close to always-wrong.

| Pattern | Why it breaks | Fix |
|---|---|---|
| `require.*(t, ...)` or `assert.*(t, ...)` inside an `Eventually`/`EventuallyWithT` closure (outer `t`, not the `*assert.CollectT` param) | First transient error fails the test instead of retrying; `FailNow` off the test goroutine can panic | Assert on the `CollectT` parameter; use `EventuallyWithT` |
| `require`/`assert` on `t` inside any `go func` | On failure after the test ends: `panic: Fail in goroutine after test has completed` — kills the whole binary | Join via `t.Cleanup(wg.Wait)` registered right after `wg.Add`; never inline `wg.Wait()` on the happy path only |
| `context.Background()` for waits/queries in a test | Ignores the test deadline; hangs mask the real failure | `t.Context()`; for cleanups `context.WithoutCancel(t.Context())` |
| `os.CreateTemp` when only file *content* is needed | Held handle (no FILE_SHARE_DELETE) makes `t.TempDir()` cleanup fail on Windows → passing test marked failed | `os.WriteFile(filepath.Join(t.TempDir(), ...), data, 0o600)` |
| Hardcoded `localhost:9200` / `127.0.0.1:9200` as a placeholder output | Output health reporting makes the agent DEGRADED at a nondeterministic moment; health asserts become a race | Per-test mock ES (`integration.StartMockES`) or `IsHealthyOrDegradedFromOutput` |
| Hardcoded `"namespace": "default"` in Fleet request bodies | Runner assigns a per-test namespace; writes hit the wrong data stream or get rejected | Interpolate `info.Namespace` |
| Test-spawned OTel collector config without `service.telemetry.metrics.level: none` | Every collector binds `:8888` by default → port collision between parallel tests | Disable internal telemetry metrics |
| Fixed listening ports of any kind | Parallel tests on one host collide | `:0`, or disable the listener if unasserted |
| Exact-count asserts on live-pipeline data: `Equal(0, len(...))`, exact doc counts, exact component counts from one status snapshot | Retries, restarts, and re-ingestion legitimately vary counts | Threshold (`LessOrEqual`/`GreaterOrEqual`) or poll until stable |
| `==` on a monotonic counter computed as `snapshot + 1` (e.g. policy revision) | Any concurrent bump skips past the expected value forever | Use the value returned by the mutating API call, compare with `>=` (`IsMinPolicyRevision`) |
| Duplicate keys in inline YAML configs | Parser silently keeps the last; the test believes it configured something it didn't | Deduplicate; read the final merged config critically |
| `filelog`/`filestream` receiver reading a file the test pre-populates, without `start_at: beginning` | Defaults to `end`; if the collector starts after the write, content is silently skipped forever | `start_at: beginning` |
| Non-fatal `assert.Eventually*` followed by unguarded indexing (`Hits.Hits[0]`) | On timeout, execution continues into an index-out-of-range panic | `require.Eventually*`, or guard the access |
| `t.Skip` without an issue link, before `define.Require`, or unconditional for a platform-specific problem | Untracked coverage loss; skips must stay discoverable and self-expiring | `t.Skip("... issues/NNN")` placed after `define.Require`, scoped to the affected platform/version |
| Zero-valued fields in Kibana/Fleet API request structs — check **every** `Create*`/`Update*` call (`CreateFleetProxy`, `CreateDownloadSource`, …); a missing `ID` marshals as `"id": ""` when the struct lacks `omitempty` | Server-side validation tightening turns tolerated `""` into a hard 400 | Set explicit unique values (`name + uuid`) on every such call, not just the ones near assertions |

## Tier 2 — semantic questions

### Every Elasticsearch query the test asserts on
- **Who generates the matching data, and is production guaranteed?** A test that waits
  for ambient events (auditd, network traffic, host logs) it never causes will pass or
  fail with host activity. The test must trigger its own events — ideally *inside* the
  poll loop, so each retry tick regenerates the signal (rule activation, restarts, and
  slow pipelines are then covered automatically).
- **Is the filter tight enough to match only that data?** Broad `exists:` queries plus
  `Hits[0]` select an arbitrary ambient document. Filter on values the test controls:
  its own tag, namespace, `process.name`, generated message. If two documents are
  *compared* (e.g. process-runtime vs otel-runtime), both sides must provably be the
  same underlying event, and build-metadata / event-type-specific fields
  (`agent.version`, `auditd.data.*`) belong in the ignore list.
- **Is a `@timestamp >= watermark` bound captured *before* the action that produces the
  document?** Capturing `time.Now()` after `Install`/`Enroll` returns excludes events
  emitted during the call — the query can then never match. (This exact bug shipped twice.)

### Every wait / Eventually
- **Poll the value you assert, not a weaker proxy.** File existence ≠ file has content;
  process exists ≠ upgrade progressing; Kibana 200 on a policy PUT ≠ agent applied it
  (gate on the applied policy revision instead).
- **Read agent-local state locally.** Fleet's agent document only advances on checkin,
  which the test cannot force. If the value exists in `elastic-agent status` /
  `fixture.ExecStatus`, poll that, never Kibana. This explicitly includes upgrade state:
  `UpgradeDetails` in Kibana's agent doc is a checkin-lagged *mirror* of agent-local
  state, not "Fleet-side state" — raising the timeout on the Kibana copy is the wrong
  fix when the local status has the value immediately.
- **"Reset then assert absence" on async streams is a race.** Draining a log buffer and
  requiring zero later occurrences fails when late writes land after the drain. Assert
  monotonic cumulative counts or post-marker occurrences instead.
- **Drive state machines by observed condition, not magic counts.** "Restart 3 times,
  sleep 10s" encodes internal timing; loop while the observable condition (reported
  version, state) still holds, under a bounded context.

### Timeouts
- **Compare every budget against the product interval that bounds it.** Fleet checkin
  long-poll is **5 minutes**: any wait for a Fleet-reported status transition must
  strictly exceed it (6m+). A budget equal to the interval has zero headroom and *will*
  flake on slow hosts.
- **Nested budgets:** an outer context must exceed the sum of the serial inner
  `Eventually` budgets it wraps.
- **Big blind timeouts are a smell in both directions.** For long operations (artifact
  downloads are ~450MB), don't just raise the number — poll the reported state
  (`UpgradeDetails.State`, `DownloadPercent`), fail fast on FAILED/ROLLBACK, detect
  stalls; then a generous ceiling is safe.

### Health assertions
- **Does the config intentionally break something?** Unreachable output, invalid input,
  missing credentials — then global-HEALTHY is wrong by construction. Assert only the
  units the test controls (`IsHealthyOrDegradedFromOutput`, or per-unit checks), or give
  the test a real mock ES.
- **Is the asserted field guaranteed populated?** e.g. `VersionInfo.Name` is
  intermittently empty for some monitoring components; empty vs wrong must be
  distinguishable.

### Environment & versions
- **OS/distro/arch:** kernel-coupled behavior (auditd, systemd, package managers) must
  pin the distros it was validated on in `define.Requirements`. Windows: file handles
  block deletion; slower hosts widen race windows.
- **Runtime topology:** don't assume beats run as separate processes (PID scraping,
  process-name regexes, process-only metric fields, one shared build hash). Pin
  `_runtime_experimental` explicitly when behavior depends on it; switch on
  `VersionInfo.Name` (`beat-v2-client` vs `beats-receiver`).
- **Dynamically resolved versions:** "latest snapshot" can equal the local build
  (`rpm -U` refuses; migration assertions become invalid) and "previous minor" may not
  exist for the platform (windows/arm64 < 9.3.0). Handle the equal-version case; gate on
  capability, not availability.
- **Third-party fixtures:** leave nothing security/protocol-relevant implicit
  (`ssl_enabled => false` if the client speaks plain TCP) — vendor defaults are computed
  from the host and change across versions.
- **Exact product log strings** in allow-lists/assertions silently break when the
  product rewords errors; prefer stable substrings or structured fields.

### Shared state & cleanup (blast radius: other tests)
- **Cluster-global ES objects** (index templates, pipelines, policies) must be named
  per-test/namespace — a hardcoded shared name means the second test silently overwrites
  the first.
- **Never mutate well-known shared Fleet objects** (`fleet-default-output`) mid-suite on
  a shared stack; it bumps policy revisions for every enrolled agent. If unavoidable, do
  it before enrollment.
- **Cleanup must survive the failure path**: registered via `t.Cleanup` (LIFO), with
  credentials (uninstall tokens) re-fetched *after* the state changes they must survive.
  A failed cleanup that leaves an installed/tamper-protected agent or root-owned
  `/tmp` dir breaks unrelated later tests.
- **Anything writing to stdout** (progress bars, spinners) must be terminated — `go test`
  output is machine-parsed and pollution fails *other* tests.

## Tier 3 — use the shared tooling

Hand-rolled equivalents of these have all caused flakes:

- **Agent lifecycle**: `define.NewFixtureFromLocalBuild` → `Prepare`/`Configure` →
  `fixture.Install(...)`. Never `PrepareAgentCommand` + `cmd.Start()` + stdout scraping —
  it yields no diagnostics on failure and leaks agent processes.
- **Config switching**: `fixture.Configure` (reload) instead of teardown/restart.
- **Logs**: `fixture.Exec(ctx, []string{"logs", ...})` instead of scraping process output.
- **Health**: `fixture.IsHealthy` only when everything is genuinely expected healthy;
  `IsHealthyOrDegradedFromOutput` when the output is intentionally absent.
- **Policy propagation barrier**: `tools.IsMinPolicyRevision` with the revision returned
  by `UpdatePolicy`.
- **Placeholder ES**: `integration.StartMockES`, not a dead `localhost:9200`
  (and never `status_reporting.enabled: false` — it masks real product bugs).
- **Doc comparisons across runtimes**: reuse the established ignore-list machinery
  (`assert_tools.go`) rather than fresh map-diff code.

When in doubt about whether a pattern has bitten before, check
[references/flake-taxonomy.md](references/flake-taxonomy.md) — it maps every category to
the commits/PRs that fixed real instances, useful for citing precedent in review
comments.
