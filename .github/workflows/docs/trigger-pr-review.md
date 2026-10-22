# Review pull requests automatically

Invokes the shared PR review workflow for eligible non-draft pull requests from trusted repository collaborators.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-pr-review.yml`](../trigger-pr-review.yml) |
| Trigger | Pull request opened, synchronized, reopened, ready for review, labeled, or unlabeled |

## Purpose

The workflow delegates automated review to `gh-aw-pr-review.lock.yml` in `elastic/ai-github-actions`.

## When it runs

The job requires a non-draft PR, excludes PRs with the `skip-auto-pr-review` label, and limits execution to authors associated as `OWNER`, `MEMBER`, or `COLLABORATOR`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | PR passes all job conditions | None | Calls the external review workflow with repository setup commands and failure-as-issue reporting disabled. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: write`. |
| Outputs | Review behavior and any comments are controlled by the external reusable workflow. |

## Operational notes

The external reviewer implementation is not checked into this repository.

## Sources

- Workflow: [`trigger-pr-review.yml`](../trigger-pr-review.yml)
