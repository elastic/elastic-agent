# Sweep coordinator status accuracy

Runs a scheduled code-quality audit focused on incorrect or stuck Elastic Agent coordinator and health-state reporting.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`sweep-coordinator-status-accuracy.yml`](../sweep-coordinator-status-accuracy.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow prompt directs the shared audit workflow to investigate coordinator, component runtime, Fleet, and monitoring status aggregation, and to report only confirmed user-observable issues.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external code-quality audit workflow with a high severity threshold, repository setup commands, and the status-accuracy audit instructions. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | The external workflow is instructed to file one issue for confirmed findings; `report-failure-as-issue` is false. |

## Operational notes

The reusable workflow implementation is external. The repository-specific audit instructions are inline in the source; the setup commands install system libraries and build Mage.

## Sources

- Workflow: [`sweep-coordinator-status-accuracy.yml`](../sweep-coordinator-status-accuracy.yml)
