# Route issue comments to Observability Agentic Workflow

Delegates every created issue-comment event to the shared Observability Agentic Workflow event handler.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-issue-comment.yml`](../trigger-obs-aw-issue-comment.yml) |
| Trigger | Issue comment created |

## Purpose

The repository workflow is a thin caller for `obs-aw-event-issue-comment.yml` in `elastic/oblt-aw`.

## When it runs

It listens to `issue_comment:created`; the caller defines no additional job condition or branch filter.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-issue-comment` | Every issue-comment event | None | Calls the external reusable workflow. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: write`, `copilot-requests: write`, `discussions: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Outputs | Event handling is owned by the external workflow. |

## Operational notes

The `elastic/oblt-aw` implementation is outside this checkout; no further event behavior is asserted.

## Sources

- Workflow: [`trigger-obs-aw-issue-comment.yml`](../trigger-obs-aw-issue-comment.yml)
- Reusable workflow: [`obs-aw-event-issue-comment.yml`](https://github.com/elastic/oblt-aw/blob/v0/.github/workflows/obs-aw-event-issue-comment.yml)
