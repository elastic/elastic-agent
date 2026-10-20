# Run the daily Observability Agentic Workflow schedule

Calls the shared scheduled Observability Agentic Workflow using the `daily` schedule profile.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-schedule-daily.yml`](../trigger-obs-aw-schedule-daily.yml) |
| Trigger | Schedule or manual dispatch |

## Purpose

The caller supplies `schedule-profile: daily` to the shared schedule workflow. Its comment explains that a separate caller handles the frequent cadence because GitHub does not identify which cron expression fired within one workflow.

## When it runs

Runs on a schedule or when manually dispatched. The workflow comment identifies this caller as the daily cadence; the cron expression is intentionally omitted here.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-schedule-daily` | Every matching event | None | Calls the external schedule workflow with `schedule-profile: daily`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: write`, `copilot-requests: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Outputs | Scheduled task routing is handled externally. |

## Operational notes

The shared `obs-aw-event-schedule.yml` implementation is not in this repository.

## Sources

- Workflow: [`trigger-obs-aw-schedule-daily.yml`](../trigger-obs-aw-schedule-daily.yml)
- Reusable workflow: [`obs-aw-event-schedule.yml`](https://github.com/elastic/oblt-aw/blob/v0/.github/workflows/obs-aw-event-schedule.yml)
