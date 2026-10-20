# Mention in Issue

This GitHub Actions workflow coordinates **Mention in Issue** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/trigger-mention-in-issue.yml`](../trigger-mention-in-issue.yml) |
| Trigger | issue_comment: types: created |

## Purpose

The workflow is named **Mention in Issue** and is configured to run the declared jobs: `run`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `issue_comment: types: created`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `run` | github.event.issue.pull_request == null && (startsWith(github.event.comment.body, '/ai') \|\| contains(github.event.comment.body, '@claude')) | None declared | elastic/ai-github-actions/.github/workflows/gh-aw-mention-in-issue.lock.yml@v0 |

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
| Permissions | `{actions: read, contents: write, copilot-requests: write, discussions: write, issues: write,   pull-requests: write}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/ai-github-actions/.github/workflows/gh-aw-mention-in-issue.lock.yml@v0` (implementation not checked in this repository).

- Workflow: [`.github/workflows/trigger-mention-in-issue.yml`](../trigger-mention-in-issue.yml)
