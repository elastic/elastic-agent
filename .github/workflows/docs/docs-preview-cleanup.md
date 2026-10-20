# Clean up documentation previews

Delegates preview deployment cleanup to the shared docs workflow when a pull request closes.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`docs-preview-cleanup.yml`](../docs-preview-cleanup.yml) |
| Trigger | Pull request closed |

## Purpose

The workflow calls the reusable cleanup workflow in `elastic/docs-actions`.

## When it runs

It listens to `pull_request_target` with the `closed` activity type. No branch filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `cleanup` | Matching closed PR event | None | Invokes the external docs preview cleanup workflow. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: none`, `deployments: write`, and `id-token: write`. |
| Outputs | Cleanup is performed by the external reusable workflow. |

## Operational notes

The shared workflow implementation is not present in this repository, so the preview naming and deletion behavior cannot be verified locally.

## Sources

- Workflow: [`docs-preview-cleanup.yml`](../docs-preview-cleanup.yml)
- Reusable workflow: [`elastic/docs-actions/.github/workflows/docs-preview-cleanup.yml`](https://github.com/elastic/docs-actions/blob/v1/.github/workflows/docs-preview-cleanup.yml)
