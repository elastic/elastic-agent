# Mention in PR

This GitHub Actions workflow coordinates **Mention in PR** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/trigger-mention-in-pr.yml`](../trigger-mention-in-pr.yml) |
| Trigger | issue_comment: types: created; pull_request_review_comment: types: created |

## Purpose

The workflow is named **Mention in PR** and is configured to run the declared jobs: `run`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `issue_comment: types: created`
- `pull_request_review_comment: types: created`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `run` | (startsWith(github.event.comment.body, '/ai') \|\| contains(github.event.comment.body, '@claude')) && (github.event.issue.pull_request != null \|\| github.event_name == 'pull_request_review_comment') | None declared | elastic/ai-github-actions/.github/workflows/gh-aw-mention-in-pr.lock.yml@v0 |

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
- External action or reusable workflow: `elastic/ai-github-actions/.github/workflows/gh-aw-mention-in-pr.lock.yml@v0` (implementation not checked in this repository).

- Workflow: [`.github/workflows/trigger-mention-in-pr.yml`](../trigger-mention-in-pr.yml)
