# Investigate stale issues

Runs the shared stale-issue investigator on a schedule or manual dispatch.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-stale-issues.yml`](../trigger-stale-issues.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The caller delegates issue investigation to `gh-aw-stale-issues-investigator.lock.yml` in `elastic/ai-github-actions`.

## When it runs

Runs on a schedule or when manually dispatched, with no branch or path filters.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external investigator with failure-as-issue reporting disabled and the listed setup commands. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | Investigation behavior is owned by the external workflow. |

## Operational notes

The reusable workflow implementation and its staleness criteria are not available in this repository.

## Sources

- Workflow: [`trigger-stale-issues.yml`](../trigger-stale-issues.yml)
