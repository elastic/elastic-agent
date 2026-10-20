# Validate docs generation structure

This GitHub Actions workflow coordinates **Validate docs generation structure** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/validate-docs-structure.yml`](../validate-docs-structure.yml) |
| Trigger | pull_request: paths: internal/edot/**, docs/scripts/update-docs/**, .github/workflows/validate-docs-structure.yml |

## Purpose

The workflow is named **Validate docs generation structure** and is configured to run the declared jobs: `validate-structure`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request: paths: internal/edot/**, docs/scripts/update-docs/**, .github/workflows/validate-docs-structure.yml`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `validate-structure` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `validate-structure`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| Set up Go | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| Install mage | magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db | Always when job runs |
|  | Inputs: `install-only` |  |
| Validate expected files for docs generation | `mage check:docsFiles` | Always when job runs |

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

Referenced local sources:

- [`.github/workflows/validate-docs-structure.yml`](../../../.github/workflows/validate-docs-structure.yml)

Referenced local sources:

- [`docs/scripts/update-docs`](../../../docs/scripts/update-docs)

## Sources

- Workflow: [`.github/workflows/validate-docs-structure.yml`](../validate-docs-structure.yml)
- Referenced local file: [`.github/workflows/validate-docs-structure.yml`](../../../.github/workflows/validate-docs-structure.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
- External action or reusable workflow: `magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db` (implementation not checked in this repository).
