# docs-deploy

This GitHub Actions workflow coordinates **docs-deploy** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/docs-deploy.yml`](../docs-deploy.yml) |
| Trigger | workflow_run: workflows: docs-build; workflow_run: types: completed |

## Purpose

The workflow is named **docs-deploy** and is configured to run the declared jobs: `deploy`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `workflow_run: workflows: docs-build`
- `workflow_run: types: completed`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `deploy` | Always when triggered | None declared | elastic/docs-actions/.github/workflows/docs-deploy.yml@v1 |

### Steps

#### `deploy`

| Step | Action or command | Condition |
| --- | --- | --- |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{actions: read, contents: read, deployments: write, id-token: write, pull-requests: write}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

Referenced local sources:

- [`.github/workflows/docs-deploy.yml`](../../../.github/workflows/docs-deploy.yml)

## Sources
- External action or reusable workflow: `elastic/docs-actions/.github/workflows/docs-deploy.yml@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/docs-deploy.yml`](../docs-deploy.yml)
- Referenced local file: [`.github/workflows/docs-deploy.yml`](../../../.github/workflows/docs-deploy.yml)
