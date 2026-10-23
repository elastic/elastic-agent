# Run the frequent Observability Agentic Workflow schedule

Calls the shared scheduled Observability Agentic Workflow using the `frequent` schedule profile.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-schedule-frequent.yml`](../trigger-obs-aw-schedule-frequent.yml) |
| Trigger | Schedule or manual dispatch |

## Purpose

The workflow routes the frequent schedule profile to the shared schedule handler. Its comment describes this as the high-cadence lane, separate from the daily profile.

## When it runs

Runs on a schedule or when manually dispatched. The source marks this caller as the frequent cadence; the cron expression is intentionally omitted.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-schedule-frequent` | Every matching event | None | Calls the external schedule workflow with `schedule-profile: frequent`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: write`, `copilot-requests: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Outputs | Scheduled task routing is handled externally. |

## Operational notes

The job comments that its permissions are the union of all jobs in the shared schedule workflow, including routes skipped by profile conditions. The reusable workflow is not checked in here.

## Sources

- Workflow: [`trigger-obs-aw-schedule-frequent.yml`](../trigger-obs-aw-schedule-frequent.yml)
