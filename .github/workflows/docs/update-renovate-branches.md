# update-renovate-branches

This GitHub Actions workflow coordinates **update-renovate-branches** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/update-renovate-branches.yml`](../update-renovate-branches.yml) |
| Trigger | workflow_dispatch; schedule |

## Purpose

The workflow is named **update-renovate-branches** and is configured to run the declared jobs: `update`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `workflow_dispatch`
- `schedule`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `update` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `update`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/elastic/active-branches@v1 | Always when job runs |
|  | Inputs: `filter-branches` |  |
| step-2 | actions/checkout@v7 | Always when job runs |
| Update baseBranches in renovate.json | `branches=$(printf '%s' "$MATRIX" \| jq -c '[.include[].branch]')` | Always when job runs |
| step-4 | peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1 | Always when job runs |
|  | Inputs: `token, commit-message, title, body, branch, base, delete-branch, labels` |  |
| step-5 | elastic/oblt-actions/slack/send@v1 | ${{ failure() }} |
|  | Inputs: `bot-token, channel-id, message` |  |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | Workflow variables: JOB_URL |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/oblt-actions/elastic/active-branches@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/update-renovate-branches.yml`](../update-renovate-branches.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1` (implementation not checked in this repository).
