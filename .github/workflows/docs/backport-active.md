# Backport to active branches

This GitHub Actions workflow coordinates **Backport to active branches** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/backport-active.yml`](../backport-active.yml) |
| Trigger | pull_request_target: types: closed, labeled; pull_request_target: branches: main |

## Purpose

The workflow is named **Backport to active branches** and is configured to run the declared jobs: `backport`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request_target: types: closed, labeled`
- `pull_request_target: branches: main`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `backport` | github.event.pull_request.merged == true &&  (    (github.event.action == 'closed' && contains(toJSON(github.event.pull_request.labels.*.name), 'backport-active-')) \|\|    (github.event.action == 'labeled' && startsWith(github.event.label.name, 'backport-active-')) )  | None declared | ubuntu-latest |

### Steps

#### `backport`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/github/backport-active@v1 | Always when job runs |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read, pull-requests: write}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/oblt-actions/github/backport-active@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/backport-active.yml`](../backport-active.yml)
