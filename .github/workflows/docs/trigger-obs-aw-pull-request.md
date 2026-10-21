# Route pull requests to Observability Agentic Workflow

Delegates selected pull-request events to the shared Observability Agentic Workflow.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-pull-request.yml`](../trigger-obs-aw-pull-request.yml) |
| Trigger | Pull request opened, synchronized, reopened, or labeled |

## Purpose

The workflow calls `obs-aw-event-pull-request.yml` in `elastic/oblt-aw` as the repository's PR-event handler.

## When it runs

It listens for `pull_request` events of type `opened`, `synchronize`, `reopened`, and `labeled`; no branch/path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-pull-request` | Every matching event | None | Calls the external reusable workflow. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: write`, `copilot-requests: write`, `discussions: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Outputs | Event handling is owned by the external workflow. |

## Operational notes

The reusable workflow is maintained outside this repository; its internal PR processing cannot be verified from this checkout.

## Sources

- Workflow: [`trigger-obs-aw-pull-request.yml`](../trigger-obs-aw-pull-request.yml)
