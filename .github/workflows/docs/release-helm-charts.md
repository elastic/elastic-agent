# release-helm-charts

This GitHub Actions workflow coordinates **release-helm-charts** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/release-helm-charts.yml`](../release-helm-charts.yml) |
| Trigger | workflow_dispatch; release: types: published |

## Purpose

The workflow is named **release-helm-charts** and is configured to run the declared jobs: `trigger-release`, `trigger-workflow`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `workflow_dispatch`
- `release: types: published`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `trigger-release` | ${{ github.event.action == 'published' && !startsWith(github.ref_name, '8.16') && !startsWith(github.ref_name, '8.17') }} | None declared | ubuntu-latest |
| `trigger-workflow` | github.event.action != 'published' | None declared | ubuntu-latest |

### Steps

#### `trigger-release`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/buildkite/run@v1 | Always when job runs |
|  | Inputs: `branch, pipeline, token, wait-for, env-vars` |  |
| step-2 | elastic/oblt-actions/slack/send@v1 | ${{ failure()  }} |
|  | Inputs: `bot-token, channel-id, message` |  |
#### `trigger-workflow`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/buildkite/run@v1 | Always when job runs |
|  | Inputs: `branch, pipeline, token, wait-for, env-vars` |  |

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

## Sources
- External action or reusable workflow: `elastic/oblt-actions/buildkite/run@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/release-helm-charts.yml`](../release-helm-charts.yml)
