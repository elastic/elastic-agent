# macos-unit-tests

This GitHub Actions workflow coordinates **macos-unit-tests** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/macos-unit-tests.yml`](../macos-unit-tests.yml) |
| Trigger | workflow_dispatch; pull_request; push: branches: main, 8.19, 9.* |

## Purpose

The workflow is named **macos-unit-tests** and is configured to run the declared jobs: `unit-tests`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `workflow_dispatch`
- `pull_request`
- `push: branches: main, 8.19, 9.*`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `unit-tests` | Always when triggered | None declared | ${{ matrix.os }} |

### Steps

#### `unit-tests`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules, fetch-depth` |  |
| step-2 | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| Install make | `brew install make` | Always when job runs |
| Install mage | `make mage` | Always when job runs |
| mage ${{ matrix.mage_target }} | `RACE_DETECTOR=true TEST_COVERAGE=true mage ${{ matrix.mage_target }}` | Always when job runs |

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

- Workflow: [`.github/workflows/macos-unit-tests.yml`](../macos-unit-tests.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
