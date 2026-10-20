# Build documentation

Delegates documentation checks and builds to the shared Elastic docs workflow for pull requests, `main` pushes, and merge groups.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`docs-build.yml`](../docs-build.yml) |
| Trigger | Pull request, push to `main`, or merge group |

## Purpose

The repository workflow calls the reusable `elastic/docs-actions` build workflow and enables Vale linting for release notes and reference documentation.

## When it runs

It runs for pull request `opened`, `synchronize`, and `reopened` events; pushes to `main`; and `merge_group` events. No path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `build` | Every matching event | None | Calls the external reusable docs build workflow with Vale enabled for `docs/release-notes/**` and `docs/reference/**`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`, `pull-requests: read`. |
| Outputs | Build and lint results are produced by the external reusable workflow. |

## Operational notes

The reusable workflow implementation is in `elastic/docs-actions` and is not checked into this repository; its internal build steps are not covered here.

## Sources

- Workflow: [`docs-build.yml`](../docs-build.yml)
- Reusable workflow: [`elastic/docs-actions/.github/workflows/docs-build.yml`](https://github.com/elastic/docs-actions/blob/v1/.github/workflows/docs-build.yml)
