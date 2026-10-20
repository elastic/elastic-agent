# catalog-info

This GitHub Actions workflow coordinates **catalog-info** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/catalog-info.yml`](../catalog-info.yml) |
| Trigger | pull_request: branches: main; pull_request: paths: catalog-info.yaml |

## Purpose

The workflow is named **catalog-info** and is configured to run the declared jobs: `validate`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request: branches: main`
- `pull_request: paths: catalog-info.yaml`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `validate` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `validate`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| step-2 | elastic/oblt-actions/elastic/validate-catalog@v1 | Always when job runs |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/oblt-actions/elastic/validate-catalog@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/catalog-info.yml`](../catalog-info.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
