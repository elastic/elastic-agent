# Investigate failed pull-request workflows

Invokes the shared PR-actions detective when a selected workflow fails for a run associated with a pull request.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-pr-actions-detective.yml`](../trigger-pr-actions-detective.yml) |
| Trigger | Completion of selected workflows |

## Purpose

The caller delegates workflow-failure investigation to `gh-aw-pr-actions-detective.lock.yml` in `elastic/ai-github-actions`.

## When it runs

It listens for completed runs of `pre-commit`, `golangci-lint`, `Validate docs generation structure`, `docs-build`, or `fragment-in-pr`. The job runs only for a failed run with at least one associated pull request.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Matching workflow failed and has PR association | Completed workflow run | Calls the external detective with setup commands and failure-as-issue reporting disabled. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: write`. |
| Outputs | Investigation behavior is external; no local artifact is declared. |

## Operational notes

The caller's reusable workflow implementation and investigation prompt are not available in this repository.

## Sources

- Workflow: [`trigger-pr-actions-detective.yml`](../trigger-pr-actions-detective.yml)
