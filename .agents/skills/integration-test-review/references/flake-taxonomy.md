# Precedent index: integration test flakes (Aug 2025 – Aug 2026)

Companion to [SKILL.md](../SKILL.md). Every rule in the skill was derived from real CI
incidents; this file is the evidence, organized by the same category vocabulary the
skill uses for findings. Use it to:

- **cite precedent in review comments** — "this exact pattern caused #15149" carries
  more weight than an unsourced rule;
- **decide edge cases** the checklist doesn't cleanly match — check whether something
  similar has bitten before;
- **audit a rule** that looks wrong or stale — trace it back to the incidents it came
  from before changing it.

Sourced from all 60 test-only commits in the window (50 touching only
`testing/integration/ess/`, 10 also touching shared test helpers), each reviewed with
full diff, PR body, and linked flaky-test issues.

## Observed frequency

How often each failure mode was the primary cause of a flake fix or skip in the window.
Use this to calibrate severity: the top two categories account for over half of all
incidents and deserve the closest reading.

| Category | Count | One-line description |
|---|---|---|
| assert-before-settled | ~12 | Asserting on state an async pipeline hasn't reached; watermark/barrier missing or on the wrong side of the producer |
| overly-strict-assertion | ~11 | Exact match / exact count / global-HEALTHY on legitimately varying data |
| environment-assumption | ~8 | OS/distro/arch/kernel/JVM/CI-image specifics; implicit runtime topology |
| test-harness-misuse | ~6 | testify misuse, goroutines outliving tests, stdout pollution, unguarded indexing |
| cross-test-interference | ~6 | Shared cluster/host state: template names, fixed ports, root-owned dirs, leftover installs |
| timeout-too-short | ~4 | Especially budgets equal to a known product interval (Fleet 5m checkin long-poll) |
| version-drift | ~3 | Same-version snapshot upgrades, beats vs agent version skew, previous-minor gaps |
| external-dependency | ~3 | Kibana API changes, DRA artifact availability, real large downloads |
| test-config-bug | ~2 | Test's own YAML silently wrong: duplicate keys, missing `start_at` |

A further ~4 incidents in the window were **not** test bugs at all: the test correctly
caught a real product defect. Those are covered under
[Patterns across incidents](#patterns-across-incidents) — the reviewer-relevant lesson
there is about how such failures were handled, not about the tests being wrong.

## assert-before-settled

- **#11038 (3e7d103977)** TestClassicAndReceiverAgentMonitoring: `time.Now()` watermark for the ES `@timestamp >= X` filter captured AFTER `InstallWithoutEnroll` — the log line it queries for is emitted *during* install, so the query could never match. Fixed by capturing the timestamp before install. **The same bug shipped again in #15172 (0d91cf0e7c)** in the OTel phase of the same test — cite both when a watermark sits after its producing action.
- **#16328 (c69e464065)** TestSystemMetricsWithLogstashOutput: polled for output *file existence* but read/parsed contents *outside* the retry loop; Logstash creates the file before writing the first record. Fixed by parsing inside `EventuallyWithT` and requiring non-nil data — poll the value you assert, not a weaker proxy.
- **#15201 (4aa75de209)** TestOtelAPMIngestion: filelog receiver without `start_at: beginning` defaults to `end`; the test wrote the file before the collector finished starting, so content was silently skipped forever. Also had `context.Background()` in wait loops, ignoring the test deadline.
- **#10004 (5372f245a0)** monitoring-probe tests: treated Kibana 200 on a policy PUT as "agent applied the policy", then immediately dialed the agent's monitoring port. Fixed by gating on `IsPolicyRevision(agentID, resp.Revision)`. Cautionary detail: the retry added alongside wrapped only `http.NewRequest` (which never fails), not `client.Do` — a retry must wrap the fallible call.
- **#11911 (b14334e263)**, after stop-gap skip **#11910**, TestFleetDownloadProxyURL: polled Fleet/Kibana's agent document for upgrade state, which only advances on an uncontrollable agent checkin, while local `elastic-agent status` had the value immediately. Fixed by switching to `fixture.ExecStatus`. Cite when a test reads agent-local state through Kibana.
- **#16329 (91498ad393)** TestPolicyReassignWithTamperProtectedEndpoint: uninstall token fetched *before* the policy reassignment it must survive; readiness keyed on `policy.id`, which flips before the tamper-protection material is durably applied — stale token on slow hosts left a tamper-protected endpoint installed on the CI host.
- **#11324 (2f2631b1e9)** TestStandaloneUpgradeRollbackOnRestarts: hardcoded "restart 3 times, sleep 10s" to drive the watcher's rollback state machine; the correct count silently encoded watcher-internal PID accounting. Fixed by looping on an observable condition (agent still reports the upgraded version).
- **#12159 (023091862c)** TestLogReloading: `zapLogs.TakeAll()` to "reset" an async log-capture buffer, then `require.Zero` on a message the earlier phase legitimately produced — the drain races the producer. Fixed with cumulative monotonic counts.
- **#14048 (f396421abb)** (skip) TestOtelElasticsearchStateStore_Agentless: one-shot assertion on the *first* `since` value after restart, gated on ES near-real-time visibility of the persisted cursor. First-sample-after-restart is unrepeatable.
- **#16052 (52aa8844f0)** auditd: the event-generating action ran once, *before* the poll loop that waits for the events, racing audit-rule activation. Fixed by generating a fresh event on every retry tick inside `EventuallyWithT`.
- **#15206 (99dc67ee2b)** TestEventLogFile (secondary cause): expected-file list built from a directory scan taken before the action under test — a snapshot-then-collect window that turned a config bug into a Windows-only flake.
- **#14121 (e3c1ffc27b)** (skip) TestSwitchToUnprivilegedDeduplication: fired five concurrent Fleet privilege-switch actions to exercise action deduplication, so the tested precondition (duplicates landing in one checkin batch) existed only when the race happened to land right — most runs never exercised the condition the test claimed to check, and when dedup genuinely failed, a duplicate action executed after the privilege drop and wedged the agent. Create preconditions deterministically (e.g. inject duplicate actions directly), never via a race. (The failures also exposed a real dedup gap, tracked in #14079.)

## overly-strict-assertion

- **#15514 (3dfe762f37)** TestMonitoringNoDuplicates: `require.Equal(0, len(buckets))` directly contradicting its own adjacent comment ("possible to have a small number") — runtime transitions legitimately re-ingest a few documents. Fixed with `LessOrEqual` against a budget. Bonus: `%d` applied to a float64 garbled the failure diagnostic.
- **#15199 (15b6967d62)** TestNetworkTraffic compare: compared `Hits[0]` of a broad `exists:` query over *ambient* TLS traffic between two phases — different destinations, legitimately different geo/TLS fields. Fixed by generating controlled traffic (dial ES on every poll tick) and filtering on it; also replaced a silent `t.Skip` on missing upstream data with `require.NotNil`.
- **The auditd sequence #15867 → #15914 → #16052 (2b6f73e61e, ec1d03a308, 52aa8844f0)**: (a) no audit rules configured, so the test asserted on data it never caused to be produced — it passed only via install-time noise; (b) selection by broad exists-filter picked heterogeneous ambient events whose field sets vary by kernel/PAM config; (c) even scoped by tag, the two runtime modes picked execve events from different processes. Stable end state: the test generates its own events, filters on its own rule tag + `process.name`, ignores event-type-specific `auditd.data.*`. Cite the whole sequence when a comparison selects "the first matching ambient document".
- **#15153 (1f4f63561c)** auditd monitoring: same lesson — pin both compared documents to the same `event.action`; ignore `auditd.data`.
- **#11257 (1fa09721ca) + #11539 (b8a142f544)** (7 tests): asserted HEALTHY while the config intentionally pointed the ES output at a dead `localhost:9200` — output health reporting works, so DEGRADED arrives at a nondeterministic moment. The interim fix (`status_reporting.enabled: false`) was later *reverted* by **#12710 (203484cde9)** because it masked real product bugs (#12586); the durable fixes are a per-test mock ES (`integration.StartMockES`) or **#11997 (ec86428439)**'s `IsHealthyOrDegradedFromOutput`, which tolerates DEGRADED only when every degraded unit is an OUTPUT unit. Cite this chain when a test suppresses status reporting instead of scoping its assertion.
- **#10153 (71ece0de92)**, after skip **#9891 (ba9c156513)**, TestBeatsReceiverLogs: asserted agent + all units HEALTHY and an exact component count while deliberately configuring an unreachable output; also managed the agent process by hand and scraped stdout, leaking an agent on failure. Fixed by asserting only what the test controls (component count, `VersionInfo.Name`, INPUT units) and using the fixture lifecycle.
- **#14911 (7047441f0a)** TestFQDN: expected policy revision computed as `snapshot + 1` with exact `==` on a monotonic counter; any concurrent bump skips past it forever. Fixed by using the revision returned by the mutating call plus `>=` (`IsMinPolicyRevision`).
- **#10851 (89c9b279d7)**: doc comparisons asserted `agent.version` equality between the beats process (beats repo version) and the beats receiver (vendored dependency version) — build-metadata drift, not behavior. Fixed via the ignore-list.
- **#11231 (259dd3e966)** (assertion skip): runtime name derived from `comp.VersionInfo.Name`, which is intermittently empty for `http/metrics-monitoring` (product bug #11162) — an empty value was indistinguishable from a wrong one.

## environment-assumption

- **#14685 (d1e89db2e8)**, and again in **#14956 (294efa35ab)**: `os.CreateTemp` keeps a handle without FILE_SHARE_DELETE; Go 1.25's `os.RemoveAll` in `t.TempDir()` cleanup then fails on Windows, marking a passing test failed. Fixed with `os.WriteFile` where only content is needed. Recurred across two PRs — cite when reviewing any test temp-file handling.
- **#14363 (86babefe16)**: Logstash pipeline fixture left SSL implicit; Logstash 9.2.2 validates host-JVM-derived `ssl_supported_protocols` (containing nil on some CI hosts) even when SSL is unused. Fixed with explicit `ssl_enabled => false`, matching the client's plain-TCP behavior.
- **#15867 (2b6f73e61e)**: auditd in passive multicast mode observes only ambient kernel activity; a quiescent host produced zero events for the full 10-minute window.
- **#10873 (05c9876946)** (skip): auditd broke on a new Debian CI image; `OS: {Type: Linux}` was narrowed to the validated distros (ubuntu, rhel). Kernel-coupled tests should pin distros.
- **#15377 (a5ae22e11e)** (skip): a previous-minor agent used as upgrade *source* can't resolve windows/arm64 packages before 9.3.0. Fixed with a self-expiring capability gate, `SupportsUpgradeSourceOnPlatform`.
- **#10537 (3ccf28da2e)**: five latent "beats are separate OS processes" assumptions (PID scraping from status messages, a process-name regex over-matching the otel collector, process-only metric fields, one shared build hash for all components) — all broke when monitoring moved in-process. Pin `_runtime_experimental` explicitly; switch on `VersionInfo.Name`.
- **#13496 (8a4ace66ce)** (also version-drift): rpm `--prefix` installs — scriptlets don't restart the service; `rpm -U` refuses same-version upgrades; data-dir migration assertions are invalid when versions are equal.
- **#10735 (d3306c51d2)** TestAgentMetricsInput: set the experimental runtime on only the *input* and left agent self-monitoring at its implicit default, so the `otel` case silently ran an untested mixed-runtime configuration (which happened to be genuinely broken — ingest-dev#6295). Pin the runtime explicitly on every subsystem the test spins up; an implicit default is an untested combination waiting to change under you.

## test-harness-misuse

- **#11499 (f32807c8af)**: `require.NoErrorf(t, ...)` inside `EventuallyWithT(func(ct *assert.CollectT))` — the first transient error fails the test instead of retrying, and `FailNow` fires off the test goroutine. The same bug was fixed at 9 more sites in **#14956 (294efa35ab)** and 2 in **#11971 (577400b0ca)** — three PRs for one grep-able pattern.
- **#13893 (0df409cba9)**: a goroutine calling `require.NoError(t, ...)` was joined by an inline `wg.Wait()` placed after fatal-capable assertions; on the failure path the goroutine outlived the test → `panic: Fail in goroutine after test completed`, killing the whole binary. Fixed with `t.Cleanup(wg.Wait)` registered immediately after `wg.Add`.
- **#15695 (c71db977a7)**: an indeterminate progress bar handed to `EnsureUserAndGroup` was never finalized and kept writing to stdout, corrupting `go test` output — *unrelated passing tests* were parsed as failed.
- **#11229 (4f8fbe9759)**: non-fatal `assert.EventuallyWithT` followed by unguarded `Hits.Hits[0]` — an index-out-of-range panic on timeout instead of a clean failure.
- **#11507 (cfa14fac0c)** (secondary): error path `fmt.Errorf("incorrect response code: %v", err)` with a nil `err` discarded the actual status code and body; the response body was never closed.
- **#10717 (020adf82d6)**: launching the agent via `PrepareAgentCommand` + `cmd.Start()` instead of `fixture.Install` — no diagnostics on failure, and a stray agent process survived the test.

## cross-test-interference

- **#11507 (cfa14fac0c)**: two tests PUT an index template under the same hardcoded name (`no-dynamic-template`) on the shared ES cluster; whichever ran second overwrote the first, silently removing its strict mapping. Name cluster-global resources after the test/namespace.
- **#12804 (7a83205bdc)**: every plain-mode otel collector binds `:8888` for internal telemetry by default — collisions between parallel tests. Fixed with `service.telemetry.metrics.level: none` in every test collector config.
- **#11971 (577400b0ca)**: a sudo test created a root-owned `/tmp/elastic-agent` fallback dir; later unprivileged tests got permission denied. Fixed with `t.Cleanup(os.RemoveAll)` in the shared `runOrSkip`.
- **#14705 (48b56d8e08)**: suite setup mutated the shared `fleet-default-output` (latency preset), bumping policy revisions for every enrolled agent — which broke TestFQDN's revision math (**#14911**). Cite this pair when a PR mutates well-known shared Fleet objects mid-run.
- **#14956 (294efa35ab)**: Fleet request bodies hardcoding `"namespace": "default"` instead of `info.Namespace` — writes landed in the wrong data stream under the runner's assigned namespace.
- **#16329 (91498ad393)**: a failed cleanup (stale uninstall token) left a tamper-protected endpoint installed on the shared CI host, poisoning subsequent tests.

## timeout-too-short

- **#15747 (fbff8ad801)** and **#14119 (b552fdf549)**: wait budgets of exactly 5 minutes against Fleet Server's 5-minute checkin long-poll — zero headroom, flaked on any added latency. Cite both when a Fleet-status wait is ≤ 5m.
- **#15135 (124e3d413a)**: a blind 5-minute process-existence wait (`WaitForWatcher`) guarded a ~450MB artifact download through a proxy chain; raising the timeout alone would make genuine failures burn the whole budget. Fixed with a state-aware wait — poll `UpgradeDetails.State`, fail fast on FAILED/ROLLBACK, detect stalls via `DownloadPercent` — after which a 15m ceiling is safe. The flake was seeded when the test was added in **#11577 (8c0f918ffb)**.
- **#11229 (4f8fbe9759)**: 2 minutes for an end-to-end install → emit → ship → searchable-in-ES path.
- **#15977 (e70a74ed43)** (caught in review, pre-merge): an outer 10m context wrapping four serial 5m `Eventually` blocks — the outer deadline must exceed the sum of the serial inner budgets.

## version-drift

- **#13496 (8a4ace66ce)**: "latest snapshot on this branch" can equal the locally built version — `rpm -U` refuses, and migration assertions become structurally invalid. Handle the equal-version case in any dynamically resolved upgrade pair.
- **#10851 (89c9b279d7)**: beats-process vs beats-receiver `agent.version` skew during dependency-bump windows.
- **#13275 (8d1bcc62b2)**: a log allow-list keyed on an exact product error string silently stopped matching when the product reworded its error wrapping.

## external-dependency

- **#14505 (e5b6a39af4)**: `ProxiesRequest.ID` without `omitempty` marshaled `"id": ""`; a Kibana-side validation tightening turned tolerated-empty into a hard 400. Don't rely on the server tolerating zero values in any `Create*`/`Update*` call.
- **#11577 (8c0f918ffb)**: a new test pulled a real ~450MB artifact from snapshots.elastic.co through two proxies, with `t.Cleanup(proxy.Close)` able to fire mid-download — seeded the #15135 timeout flake.
- **#10200 (cfd9085c1a)**: an unconditional `t.Skip` for a windows/arm64-only DRA gap disabled upgrade coverage on *all* platforms. Scope skips to the affected platform so they self-expire.

## test-config-bug

- **#15206 (99dc67ee2b)**: two `agent.monitoring:` keys in one inline YAML document — the parser keeps the last, silently discarding `metrics: false`; surfaced as a Windows-only timing flake.
- **#14705 (48b56d8e08)**: left `preset: latency` immediately followed by `preset: balanced` in the same output block, silently defeating the change.
- **#15201 (4aa75de209)**: missing `start_at: beginning` on a filelog receiver reading a pre-populated file (defaults to `end`).

## Patterns across incidents

Worth knowing when judging a borderline finding or reviewing a proposed flake fix:

- **First fixes routinely treat the symptom, not the nondeterminism.** auditd took four commits to converge; the placeholder-output problem took three approaches; TestFleetDownloadProxyURL went seed (#11577) → skip (#11910) → fix (#11911) → timeout rework (#15135); the watermark bug shipped twice in the same test. When reviewing a flake fix, ask whether the underlying nondeterminism is gone or merely made less likely — cite these chains if it isn't.
- **Not every CI failure is a test bug — and loosening a correct test is the worst outcome.** In ~4 incidents the test rightly caught a real product defect: #15107 re-enabled an assertion that had been correct all along once the receiver-naming bug was fixed; #14048 and #14121 were suspected product bugs handled with tracked skips; and the `status_reporting.enabled: false` escape hatch had to be reverted (#12710) precisely because it hid real status regressions (#12586). When a "flaky" test tracks to product misbehavior, the right response is a product fix or an issue-linked skip — never weakening the assertion until it can no longer catch the bug.
- **Skips have a convention**: `t.Skip("… link to issue …")` placed *after* `define.Require` (explicit review feedback on #14048), scoped to the affected platform/version where possible so coverage elsewhere survives and the skip self-expires.
- **Refactors of shared test infrastructure can introduce flakes elsewhere**: #14705's mutation of `fleet-default-output` broke an unrelated test's revision math (#14911). A change that touches shared stack state or suite-level setup needs an interference review even if no test logic changed.
- **The process-vs-otel document comparison idiom** (same data collected under both runtimes, compared via `AssertMapsEqual` + ignore-lists in `assert_tools.go`) is the single flakiest pattern in the suite. Its stable form, converged on across #15199/#15153/#16052/#10851: the test generates the events itself, both sides are filtered to provably the same underlying event, and build-metadata plus event-type-specific fields are ignored. Hold any new comparison of this shape to that standard.
