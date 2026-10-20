# pre-commit

This GitHub Actions workflow coordinates **pre-commit** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/pre-commit.yml`](../pre-commit.yml) |
| Trigger | pull_request; push: branches: main, 8.*, 9.* |

## Purpose

The workflow is named **pre-commit** and is configured to run the declared jobs: `pre-commit`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request`
- `push: branches: main, 8.*, 9.*`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `pre-commit` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `pre-commit`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/pre-commit@v1 | Always when job runs |

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
- External action or reusable workflow: `elastic/oblt-actions/pre-commit@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/pre-commit.yml`](../pre-commit.yml)
