# docs-build

This GitHub Actions workflow coordinates **docs-build** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/docs-build.yml`](../docs-build.yml) |
| Trigger | pull_request: types: opened, synchronize, reopened; push: branches: main; merge_group |

## Purpose

The workflow is named **docs-build** and is configured to run the declared jobs: `build`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request: types: opened, synchronize, reopened`
- `push: branches: main`
- `merge_group`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `build` | Always when triggered | None declared | elastic/docs-actions/.github/workflows/docs-build.yml@v1 |

### Steps

#### `build`

| Step | Action or command | Condition |
| --- | --- | --- |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read, pull-requests: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

Referenced local sources:

- [`.github/workflows/docs-build.yml`](../../../.github/workflows/docs-build.yml)

## Sources
- External action or reusable workflow: `elastic/docs-actions/.github/workflows/docs-build.yml@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/docs-build.yml`](../docs-build.yml)
- Referenced local file: [`.github/workflows/docs-build.yml`](../../../.github/workflows/docs-build.yml)
