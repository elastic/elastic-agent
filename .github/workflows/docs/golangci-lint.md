# golangci-lint

This GitHub Actions workflow coordinates **golangci-lint** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/golangci-lint.yml`](../golangci-lint.yml) |
| Trigger | push: branches: main, 8.19, 9.*; push: paths: **/*.go, **/go.mod, **/go.sum, .golangci.yml, .golangci-lint-version, .github/workflows/golangci-lint.yml; pull_request: paths: **/*.go, **/go.mod, **/go.sum, .golangci.yml, .golangci-lint-version, .github/workflows/golangci-lint.yml |

## Purpose

The workflow is named **golangci-lint** and is configured to run the declared jobs: `golangci`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `push: branches: main, 8.19, 9.*`
- `push: paths: **/*.go, **/go.mod, **/go.sum, .golangci.yml, .golangci-lint-version, .github/workflows/golangci-lint.yml`
- `pull_request: paths: **/*.go, **/go.mod, **/go.sum, .golangci.yml, .golangci-lint-version, .github/workflows/golangci-lint.yml`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `golangci` | Always when triggered | None declared | ${{  matrix.os }} |

### Steps

#### `golangci`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| step-2 | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| golangci-lint | golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a | Always when job runs |
|  | Inputs: `version-file, args, only-new-issues` |  |

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

- [`.github/workflows/golangci-lint.yml`](../../../.github/workflows/golangci-lint.yml)

## Sources

- Workflow: [`.github/workflows/golangci-lint.yml`](../golangci-lint.yml)
- Referenced local file: [`.github/workflows/golangci-lint.yml`](../../../.github/workflows/golangci-lint.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
- External action or reusable workflow: `golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` (implementation not checked in this repository).
