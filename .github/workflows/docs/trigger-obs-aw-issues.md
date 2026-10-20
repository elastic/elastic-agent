# Route issue events to Observability Agentic Workflow

Delegates selected issue events and manual dispatches to the shared Observability Agentic Workflow.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-issues.yml`](../trigger-obs-aw-issues.yml) |
| Trigger | Issue opened, labeled, or edited; manual dispatch |

## Purpose

The workflow calls `obs-aw-event-issues.yml` in `elastic/oblt-aw` as the repository's issue-event handler.

## When it runs

It listens to issue `opened`, `labeled`, and `edited` activity types, and supports `workflow_dispatch`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-issues` | Every matching event | None | Calls the external reusable workflow. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: write`, `copilot-requests: write`, `discussions: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Outputs | Event handling is owned by the external workflow. |

## Operational notes

The external reusable workflow implementation is not part of this repository; its issue routing logic could not be inspected locally.

## Sources

- Workflow: [`trigger-obs-aw-issues.yml`](../trigger-obs-aw-issues.yml)
- Reusable workflow: [`obs-aw-event-issues.yml`](https://github.com/elastic/oblt-aw/blob/v0/.github/workflows/obs-aw-event-issues.yml)
