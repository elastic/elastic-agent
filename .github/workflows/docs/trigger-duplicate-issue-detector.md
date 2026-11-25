# Detect duplicate issues

Invokes the shared duplicate-issue detector when an eligible user opens an issue.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-duplicate-issue-detector.yml`](../trigger-duplicate-issue-detector.yml) |
| Trigger | Issue opened |

## Purpose

The workflow delegates issue comparison to `gh-aw-duplicate-issue-detector.lock.yml` in `elastic/ai-github-actions`.

## When it runs

It listens to `issues:opened`. The job runs only when the issue author's association is `OWNER`, `MEMBER`, or `COLLABORATOR`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Eligible issue author | None | Calls the external detector with related-issue detection disabled and failure-as-issue reporting disabled. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `discussions: write`, `issues: write`, `pull-requests: read`. |
| Outputs | Any detector response is managed by the external reusable workflow. |

## Operational notes

The detector implementation and its duplicate-matching logic are not present in this repository.

## Sources

- Workflow: [`trigger-duplicate-issue-detector.yml`](../trigger-duplicate-issue-detector.yml)
