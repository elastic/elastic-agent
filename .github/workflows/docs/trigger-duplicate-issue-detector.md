# Duplicate Issue Detector

This GitHub Actions workflow coordinates **Duplicate Issue Detector** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/trigger-duplicate-issue-detector.yml`](../trigger-duplicate-issue-detector.yml) |
| Trigger | issues: types: opened |

## Purpose

The workflow is named **Duplicate Issue Detector** and is configured to run the declared jobs: `run`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `issues: types: opened`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `run` | contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.issue.author_association) | None declared | elastic/ai-github-actions/.github/workflows/gh-aw-duplicate-issue-detector.lock.yml@v0 |

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
| Permissions | `{actions: read, contents: read, copilot-requests: write, discussions: write, issues: write,   pull-requests: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/ai-github-actions/.github/workflows/gh-aw-duplicate-issue-detector.lock.yml@v0` (implementation not checked in this repository).

- Workflow: [`.github/workflows/trigger-duplicate-issue-detector.yml`](../trigger-duplicate-issue-detector.yml)
