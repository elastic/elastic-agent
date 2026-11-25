# Report flaky Buildkite tests

Runs the shared flaky-test reporter on a schedule or manual dispatch and opens issues for detected failures within its configured limit.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`report-buildkite-flaky-tests.yml`](../report-buildkite-flaky-tests.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow asks the external Buildkite flaky-report action to analyze the `elastic-agent-ci` test suite and report recent flaky tests as GitHub issues.

## When it runs

Runs on a schedule or when manually dispatched. No branch or path filters are declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Creates an ephemeral GitHub token and passes test-suite, time-window, issue-label, issue-limit, and Buildkite credentials to the external report action. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Repository, `elastic` organization, suite ID `elastic-agent-ci`, one-day lookback, and a maximum of 10 issues. |
| Permissions | `contents: read`; job grants `id-token: write`. |
| Outputs | Issues are created by the external action with the configured title prefix and label. |
| Secrets | `BUILDKITE_TEST_ENGINE_TOKEN`; the GitHub token is provided by the token-minting action. |

## Operational notes

The action implementation and its deduplication rules are external to this repository.

## Sources

- Workflow: [`report-buildkite-flaky-tests.yml`](../report-buildkite-flaky-tests.yml)
