# Sweeper: Fleet Enrollment and Communication Resilience

This GitHub Actions workflow coordinates **Sweeper: Fleet Enrollment and Communication Resilience** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/sweep-fleet-enrollment-resilience.yml`](../sweep-fleet-enrollment-resilience.yml) |
| Trigger | schedule; workflow_dispatch |

## Purpose

The workflow is named **Sweeper: Fleet Enrollment and Communication Resilience** and is configured to run the declared jobs: `run`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `schedule`
- `workflow_dispatch`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `run` | Always when triggered | None declared | elastic/ai-github-actions/.github/workflows/gh-aw-code-quality-audit.lock.yml@v0 |

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
| Permissions | `{actions: read, contents: read, copilot-requests: write, issues: write, pull-requests: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/ai-github-actions/.github/workflows/gh-aw-code-quality-audit.lock.yml@v0` (implementation not checked in this repository).

- Workflow: [`.github/workflows/sweep-fleet-enrollment-resilience.yml`](../sweep-fleet-enrollment-resilience.yml)
