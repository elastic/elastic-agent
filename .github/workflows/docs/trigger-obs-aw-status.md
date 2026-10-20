# Route Buildkite failures to Observability Agentic Workflow

Delegates failed Buildkite status events to the shared Observability Agentic Workflow status handler.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-obs-aw-status.yml`](../trigger-obs-aw-status.yml) |
| Trigger | GitHub status event |

## Purpose

The workflow routes only failing status contexts containing `buildkite` to the external status handler and passes the Buildkite log API token under the expected secret name.

## When it runs

It listens to `status` events. The job requires `github.event.state == 'failure'` and a context containing `buildkite`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run-obs-aw-status` | Status is a Buildkite failure | None | Calls the external status workflow and maps `BUILDKITE_LOGS_API_TOKEN` to `BUILDKITE_API_TOKEN`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Caller grants `contents: read`; job grants `actions: read`, `contents: read`, `copilot-requests: write`, `id-token: write`, `issues: write`, and `pull-requests: write`. |
| Secrets | `BUILDKITE_LOGS_API_TOKEN` is passed as `BUILDKITE_API_TOKEN`. |

## Operational notes

The `elastic/oblt-aw` status-handler implementation is external and not checked into this repository.

## Sources

- Workflow: [`trigger-obs-aw-status.yml`](../trigger-obs-aw-status.yml)
