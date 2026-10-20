# Sweep upgrade and rollback lifecycle

Runs a scheduled code-quality audit focused on upgrade markers, platform-specific rollback, watcher state, and recovery behavior.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`sweep-upgrade-lifecycle.yml`](../sweep-upgrade-lifecycle.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The inline audit instructions direct the shared workflow to trace upgrade and rollback paths and report confirmed failures that users could encounter during normal upgrades.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external code-quality audit workflow with a high severity threshold, setup commands, and upgrade-lifecycle instructions. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | The external workflow is instructed to file one issue for confirmed findings; `report-failure-as-issue` is false. |

## Operational notes

The reusable audit implementation is external. Setup installs system libraries and builds Mage; the source prompt requests platform-specific findings.

## Sources

- Workflow: [`sweep-upgrade-lifecycle.yml`](../sweep-upgrade-lifecycle.yml)
