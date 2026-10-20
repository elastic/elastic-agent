# Validate catalog metadata

Runs the external catalog validator for pull requests that change `catalog-info.yaml` on `main`.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`catalog-info.yml`](../catalog-info.yml) |
| Trigger | Pull request to `main` changing `catalog-info.yaml` |

## Purpose

The workflow delegates validation of the catalog file—which declares the Elastic Agent component and Buildkite resources—to `elastic/oblt-actions/elastic/validate-catalog@v1`.

## When it runs

It runs for pull requests targeting `main` when the changed paths include `catalog-info.yaml`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `validate` | Matching pull request | None | Checks out the repository and runs the external catalog validation action. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Workflow and job grant `contents: read`; the job also grants `packages: read`. |
| Outputs | Validation result is reported by the external action. |

## Operational notes

The action implementation is outside this repository, so its validation rules are not described here.

## Sources

- Workflow: [`catalog-info.yml`](../catalog-info.yml)
- Catalog metadata: [`catalog-info.yaml`](../../../catalog-info.yaml)
