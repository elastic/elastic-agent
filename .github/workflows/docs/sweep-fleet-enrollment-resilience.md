# Sweep Fleet enrollment resilience

Runs a scheduled code-quality audit focused on Fleet enrollment, check-in, re-enrollment, and liveness resilience.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`sweep-fleet-enrollment-resilience.yml`](../sweep-fleet-enrollment-resilience.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The inline audit instructions direct the shared workflow to investigate enrollment state, Fleet communication/backoff, and liveness behavior, and to report only confirmed scenarios possible in normal agent operation.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external code-quality audit workflow with a high severity threshold, repository setup commands, and Fleet resilience instructions. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | The external workflow is instructed to file one issue for confirmed findings; `report-failure-as-issue` is false. |

## Operational notes

The external reusable workflow is not present locally. The source includes setup commands to install required system libraries and build Mage.

## Sources

- Workflow: [`sweep-fleet-enrollment-resilience.yml`](../sweep-fleet-enrollment-resilience.yml)
