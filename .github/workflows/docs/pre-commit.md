# Run pre-commit checks

Delegates pre-commit checks to the shared Elastic pre-commit action on pull requests and selected branch pushes.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`pre-commit.yml`](../pre-commit.yml) |
| Trigger | Pull request or push to `main`, `8.*`, or `9.*` |

## Purpose

The workflow calls `elastic/oblt-actions/pre-commit@v1`; its detailed check set is maintained by that external action.

## When it runs

It runs for pull requests and pushes to `main`, `8.*`, and `9.*`. No path filter is declared.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `pre-commit` | Every matching event | None | Runs the shared pre-commit action on `ubuntu-latest`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`. |
| Outputs | Check results are reported by the external action. |

## Operational notes

The action implementation and its exact hook list are not available in this repository.

## Sources

- Workflow: [`pre-commit.yml`](../pre-commit.yml)
