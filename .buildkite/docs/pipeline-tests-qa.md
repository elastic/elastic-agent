# Agentless QA quality-gate snippet

This environment-specific snippet waits for initial health metrics and triggers the shared serverless quality-gates pipeline for QA.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.tests-qa.yaml`](../pipeline.tests-qa.yaml), selected by [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml) |
| Trigger | The external quality-gate seedling runner selects this snippet; the `ENVIRONMENT`-to-snippet mapping is not checked into this repository. |

## Purpose

The snippet defines the Agentless QA checks passed to `serverless-quality-gates`. Its comments specify that failure prevents progression to the next stage.

## When it runs

The snippet contains QA-specific checks (`TARGET_ENV=qa`). No independent branch or event filter is defined here. The exact `ENVIRONMENT` value that selects it is determined by the external seedling runner.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Health-metric wait | Every snippet execution | None declared | Sleeps for 10 minutes, then waits for completion. |
| Observability gates | After the wait | Wait step | Triggers `serverless-quality-gates` on `main` with `TARGET_ENV=qa`, service identity, SLO/reconcile/restart/log and synthetics checks, a 10% maximum error percentage, and deployment-slice input. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `SERVICE_VERSION` (shortened to 12 characters) and optional `DEPLOYMENT_SLICES` are passed to the downstream build. |
| Outputs | A downstream quality-gates build whose result determines the QA stage result. |
| Permissions | Buildkite trigger permission for `serverless-quality-gates` is required. |
| Secrets | No secret values are referenced in this snippet. |

## Operational notes

The trigger sets `MAX_FAILURES=1`, requests at least two synthetics runs, and polls at `180s` intervals up to the configured maximum. The actual checks and thresholds are owned by the downstream pipeline.

## Sources and history

- Snippet and dispatcher: [`pipeline.tests-qa.yaml`](../pipeline.tests-qa.yaml), [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml)
- Relevant history: [`561d4c5d73`](https://github.com/elastic/elastic-agent/commit/561d4c5d73) increases the synthetics polling window.
