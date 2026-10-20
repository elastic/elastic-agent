# PR Actions Detective

This GitHub Actions workflow coordinates **PR Actions Detective** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/trigger-pr-actions-detective.yml`](../trigger-pr-actions-detective.yml) |
| Trigger | workflow_run: workflows: pre-commit, golangci-lint, Validate docs generation structure, docs-build, fragment-in-pr; workflow_run: types: completed |

## Purpose

The workflow is named **PR Actions Detective** and is configured to run the declared jobs: `run`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `workflow_run: workflows: pre-commit, golangci-lint, Validate docs generation structure, docs-build, fragment-in-pr`
- `workflow_run: types: completed`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `run` | github.event.workflow_run.conclusion == 'failure' && toJSON(github.event.workflow_run.pull_requests) != '[]' | None declared | elastic/ai-github-actions/.github/workflows/gh-aw-pr-actions-detective.lock.yml@v0 |

### Steps

#### `run`

| Step | Action or command | Condition |
| --- | --- | --- |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{actions: read, contents: read, copilot-requests: write, issues: write, pull-requests: write}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/ai-github-actions/.github/workflows/gh-aw-pr-actions-detective.lock.yml@v0` (implementation not checked in this repository).

- Workflow: [`.github/workflows/trigger-pr-actions-detective.yml`](../trigger-pr-actions-detective.yml)
