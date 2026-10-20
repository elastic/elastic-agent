# Patrol documentation

Runs the shared documentation patrol workflow on a schedule or manual dispatch.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-docs-patrol.yml`](../trigger-docs-patrol.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The caller runs `gh-aw-docs-patrol.lock.yml` from `elastic/ai-github-actions` and provides setup commands for repository tooling.

## When it runs

Runs on a schedule or when manually dispatched, with no branch/path filter.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external docs patrol workflow with failure-as-issue reporting disabled and installs the listed system libraries and Mage prerequisites. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: write`, `copilot-requests: write`, `issues: write`, `pull-requests: write`. |
| Outputs | The external workflow may update repository content or issues/PRs under the granted permissions. |

## Operational notes

The reusable workflow implementation is external, so its documentation audit process cannot be confirmed from this repository alone.

## Sources

- Workflow: [`trigger-docs-patrol.yml`](../trigger-docs-patrol.yml)
