# Integration Test Framework

## Test organisation

Integration tests live under `testing/integration/`. The subdirectory reflects the test group name used in artifact filenames:

| Directory | Group name | Typical focus |
|---|---|---|
| `testing/integration/ess/` | varies by suite | ESS (Elastic Cloud) scenarios — fleet-managed, network traffic, monitoring |
| `testing/integration/` (root) | varies | Standalone and mixed scenarios |
| `pkg/testing/` | — | Shared test helpers (fixtures, assertions, fleet client) |

The test suite name (`TestNetworkTraffic`, `TestUpgradeFleetManagedElasticAgent`, etc.) maps directly to the Go `testing.T` top-level test function. Subtests (`/otel`, `/process`, `/compare`) are `/`-separated suffixes.

## Finding a test by name

```bash
grep -rn "func TestNetworkTraffic" testing/integration/ pkg/testing/
```

For group runner tests (where the suite is defined with `define.Run`):
```bash
grep -rn "TestBeatsMetrics\|func.*BeatsMetrics" testing/integration/
```

## Diagnostics bundle naming

Each agent that calls `diagnostics collect` during a test writes a zip file named:

```
<TestName>-<RFC3339-timestamp>-diagnostics.zip
```

Subtests use `/` replaced with `-`:
- Test `TestNetworkTraffic/TestBeatsMetrics/otel` → `TestNetworkTraffic-TestBeatsMetrics-otel-2026-05-20T14-30-06Z-diagnostics.zip`

When a test runs multiple agents (e.g. fleet-server + agent under test), each produces its own zip at roughly the same timestamp. Both will match the sanitized test-name prefix — match them in step 5 and use both for cross-agent analysis.

```bash
<ITRCA> match "$RCA_DIR" "TestNetworkTraffic/TestBeatsMetrics/otel"
```

If multiple bundles match, pick the one whose timestamp is closest to the JUnit failure `timestamp` attribute. The fleet-server bundle and the agent-under-test bundle serve different purposes:
- **Agent bundle**: component states, agent logs, OTel merged config — primary diagnostic.
- **Fleet-server bundle**: enrollment/checkin logs — useful when the failure is in policy delivery or agent check-in.

## JUnit XML structure

File: `build/TEST-<SuiteName>.integration.xml`

Key attributes on `<testcase>`:
- `classname` — usually the Go package path
- `name` — full test name including subtests, e.g. `TestNetworkTraffic/TestBeatsMetrics/otel`
- `time` — elapsed seconds
- `timestamp` — RFC3339 start time of that test case

The `<failure>` child element contains the assertion message (first ~25 lines shown by `<ITRCA> junit`). The message typically includes:
- The `require.*` or `assert.*` call that failed
- The `t.Logf` output emitted during the test
- A Go stacktrace pointing at the failing assertion

```bash
<ITRCA> junit "$RCA_DIR"                          # all failures, 25 lines each
<ITRCA> junit "$RCA_DIR" TestNetworkTraffic       # filter to one suite
```

## gotestsum NDJSON output

File: `build/TEST-<SuiteName>.integration.out.json`

Each line is a JSON object:
```json
{"Test": "TestNetworkTraffic/TestBeatsMetrics/otel", "Action": "output", "Output": "    network_traffic_monitoring_test.go:123: waiting for agent healthy\n", "Time": "2026-05-20T14:22:31.5Z"}
```

Actions: `run`, `output`, `pass`, `fail`, `skip`.

The `output` lines include everything written to `t.Log` / `t.Logf`, which is where tests emit progress messages like "waiting for agent healthy after otel switch: ..." and "could not fetch events for network_traffic: ...".

```bash
<ITRCA> testlog "$RCA_DIR" "TestNetworkTraffic/TestBeatsMetrics/otel"
```

This streams all `output` lines for the named test in order, making it easy to see the polling loop progress and where it got stuck.

## Key test helpers

| Helper | Location | Purpose |
|---|---|---|
| `agentFixture.ExecStatus` | `pkg/testing/fixture.go` | Runs `elastic-agent status` on the remote agent |
| `agentFixture.IsHealthy` | `pkg/testing/fixture.go` | Checks agent returns HEALTHY status |
| `agentFixture.ExecDiagnostics` | `pkg/testing/fixture.go` | Triggers diagnostics collection |
| `require.Eventually` | testify | Polls a condition with timeout + interval |
| `triggerFreshTLSConnection` | test file | Dials the ES HTTPS endpoint to produce a network_traffic event |

## TEST_INTEG_CLEAN_ON_EXIT

When set to `false`, the test framework does not remove the agent installation and test VM after a test failure. This preserves:
- The agent's data directory and logs
- Any diagnostics not yet collected
- The running agent process for interactive inspection

Useful for re-running locally: `TEST_INTEG_CLEAN_ON_EXIT=false TEST_PLATFORMS="linux/amd64" AGENT_VERSION="9.5.0-SNAPSHOT" TEST_PACKAGES="tar.gz" mage integration:single TestNetworkTraffic`
