# Integration Test Framework

## Test organisation

Integration tests live in Go packages under `testing/integration/`. The package is the Test Engine *scope* (e.g. `github.com/elastic/elastic-agent/testing/integration/ess`); the *group* each test runs in is declared in its `define.Require(... Group: integration.<X>)` (values in `testing/integration/groups.go`), and the group is what shows up in CI job names and JUnit file names.

| Directory | Typical focus |
|---|---|
| `testing/integration/ess/` | ESS (Elastic Cloud) scenarios — fleet-managed, upgrades, packages (rpm/deb), monitoring, network traffic |
| `testing/integration/k8s/` | Kubernetes (kind) — Helm charts, kustomize, container images |
| `testing/integration/serverless/` | Serverless projects |
| `testing/integration/beats/`, `leak/` | Beats-specific and resource-leak tests |
| `pkg/testing/` | Shared test framework: fixtures, install/upgrade helpers, Fleet/ES clients, `define` |

The test suite name (`TestNetworkTraffic`, `TestUpgradeFleetManagedElasticAgent`, etc.) maps directly to the Go `testing.T` top-level test function. Subtests (`/otel`, `/process`, `/compare`) are `/`-separated suffixes.

## Finding a test by name

```bash
grep -rn "func TestNetworkTraffic" testing/integration/ pkg/testing/
```

For subtests (`t.Run` names, or suite methods run via testify `suite.Run`), search for the subtest name without the parent:
```bash
grep -rn "TestBeatsMetrics\|func.*BeatsMetrics" testing/integration/
```

Subtest names in CI replace spaces with `_` — `Upgrade_RPM_from_9.0` is `t.Run("Upgrade RPM from 9.0", …)` or a formatted variant of it.

## Diagnostics bundle naming

Each agent that calls `diagnostics collect` during a test writes a zip file named:

```
<TestName>-<RFC3339-timestamp>-diagnostics.zip
```

Subtests use `/` replaced with `-`:
- Test `TestNetworkTraffic/TestBeatsMetrics/otel` → `TestNetworkTraffic-TestBeatsMetrics-otel-2026-05-20T14-30-06Z-diagnostics.zip`

The prefix is fixed the first time a fixture asks for it (`Fixture.FileNamePrefix` in `pkg/testing/fixture.go`), so the test-name part is the test that *created* the fixture — for suite-style tests that can be the parent rather than the failing subtest. List candidates with `ls "$RCA_DIR"/build/diagnostics/<TopLevelTest>-*`.

When a test runs multiple agents (e.g. fleet-server + agent under test), each produces its own zip at roughly the same timestamp. Use both for cross-agent analysis.

If multiple bundles match, pick the one closest to the test's failure time — the `Time` of its gotestsum `fail` event (JUnit testcases carry no timestamp; see [artifacts.md](artifacts.md)). The fleet-server bundle and the agent-under-test bundle serve different purposes:
- **Agent bundle**: component states, agent logs, OTel merged config — primary diagnostic.
- **Fleet-server bundle**: enrollment/checkin logs — useful when the failure is in policy delivery or agent check-in.

## Test results

JUnit XML and gotestsum NDJSON file names, structure, and extraction recipes are in [artifacts.md](artifacts.md) §"Reading test output". In short: JUnit `<failure>` has the assertion; gotestsum `output` events carry every `t.Log` line with a timestamp, which is where tests emit progress messages like "waiting for agent healthy after otel switch: ..." — the place to see a polling loop get stuck.

## Key test helpers

| Helper | Location | Purpose |
|---|---|---|
| `agentFixture.ExecStatus` | `pkg/testing/fixture.go` | Runs `elastic-agent status` on the remote agent |
| `agentFixture.IsHealthy` | `pkg/testing/fixture.go` | Checks agent returns HEALTHY status |
| `agentFixture.ExecDiagnostics` | `pkg/testing/fixture.go` | Triggers diagnostics collection |
| `require.Eventually` | testify | Polls a condition with timeout + interval |
| `triggerFreshTLSConnection` | test file | Dials the ES HTTPS endpoint to produce a network_traffic event |

## Reproducing

To re-run a single test, see [docs/test-framework-dev-guide.md](../../../../docs/test-framework-dev-guide.md) — e.g. `mage integration:single TestNetworkTraffic` with `TEST_PLATFORMS`, `AGENT_VERSION`, and `TEST_PACKAGES` set. `TEST_INTEG_CLEAN_ON_EXIT=false` (the local default) keeps mage artifacts and `.integration-cache` after the run.
