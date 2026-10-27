# Deploy documentation

Starts the shared documentation deployment workflow after a `docs-build` workflow completes.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`docs-deploy.yml`](../docs-deploy.yml) |
| Trigger | Completion of the `docs-build` workflow |

## Purpose

The workflow delegates deployment to `elastic/docs-actions` and passes the same Vale configuration used by the repository's docs-build workflow.

## When it runs

It listens for `workflow_run` completion events from the workflow named `docs-build`. The checked-in definition does not declare a branch or conclusion condition.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `deploy` | `docs-build` completes | The named workflow run | Calls the external reusable docs deployment workflow. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`, `deployments: write`, `id-token: write`, `pull-requests: write`, and `actions: read`. |
| Outputs | Deployment behavior and artifacts are managed by the external reusable workflow. |

## Operational notes

The external implementation is not checked in here. The caller enables Vale for `docs/release-notes/**` and `docs/reference/**`.

## Sources

- Workflow: [`docs-deploy.yml`](../docs-deploy.yml)
