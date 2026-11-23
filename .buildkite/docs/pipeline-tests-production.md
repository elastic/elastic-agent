# Agentless production quality-gate snippet

This environment-specific snippet waits for initial health metrics, runs production-canary observability gates, and adds a bake period before promotion continues.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.tests-production.yaml`](../pipeline.tests-production.yaml), selected by [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml) |
| Trigger | The external quality-gate seedling runner selects this snippet; the `ENVIRONMENT`-to-snippet mapping is not checked into this repository. |

## Purpose

The snippet defines production Agentless checks passed to `serverless-quality-gates`. Its comments state that a failed build prevents further progression to the next stage.

## When it runs

The snippet contains production checks. The 10-minute health wait is unconditional; its observability-gates trigger and one-hour bake step run only when `ENVIRONMENT=production-canary`. The external seedling runner's mapping from its input environment to this file is not available in this checkout.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Health-metric wait | Every snippet execution | None declared | Sleeps for 10 minutes, then waits for completion. |
| Observability gates | `ENVIRONMENT=production-canary` | Wait step | Triggers `serverless-quality-gates` on `main` with production checks, a 2% maximum error percentage, synthetics, and deployment-slice input. |
| Bake period | `ENVIRONMENT=production-canary` | Wait step | Sleeps for one hour before promotion proceeds. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `SERVICE_VERSION` (shortened to 12 characters) and optional `DEPLOYMENT_SLICES` are passed to the downstream build. |
| Outputs | Downstream quality-gates result and, for canary environment, a one-hour bake delay. |
| Permissions | Buildkite trigger permission for `serverless-quality-gates` is required. |
| Secrets | No secret values are referenced in this snippet. |

## Operational notes

The production trigger enables alert checks in addition to reconcile, container restart, error-rate, SLO, and synthetics checks. It sets `MAX_FAILURES=1`, requests at least two synthetics runs, and polls at `180s` intervals up to the configured maximum. The downstream pipeline owns the actual check implementation.

## Sources and history

- Snippet and dispatcher: [`pipeline.tests-production.yaml`](../pipeline.tests-production.yaml), [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml)
- Relevant history: [`561d4c5d73`](https://github.com/elastic/elastic-agent/commit/561d4c5d73) increases the synthetics polling window.
