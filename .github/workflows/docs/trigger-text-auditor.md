# Audit repository text

Runs the shared text auditor on a schedule or manual dispatch.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-text-auditor.yml`](../trigger-text-auditor.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow calls `gh-aw-text-auditor.lock.yml` in `elastic/ai-github-actions` and supplies setup commands for repository tooling.

## When it runs

Runs on a schedule or when manually dispatched. No branch or path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external text auditor with failure-as-issue reporting disabled and the listed setup commands. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | Audit behavior is owned by the external reusable workflow. |

## Operational notes

The external workflow implementation and its text-audit criteria are not checked into this repository.

## Sources

- Workflow: [`trigger-text-auditor.yml`](../trigger-text-auditor.yml)
