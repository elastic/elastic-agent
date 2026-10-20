# updatecli-compose

This GitHub Actions workflow coordinates **updatecli-compose** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/updatecli-compose.yml`](../updatecli-compose.yml) |
| Trigger | workflow_dispatch; schedule |

## Purpose

The workflow is named **updatecli-compose** and is configured to run the declared jobs: `compose`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `workflow_dispatch`
- `schedule`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `compose` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `compose`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
| Get token | elastic/oblt-actions/github/create-token@v1 | Always when job runs |
| step-3 | docker/login-action@dbcb813823bdd20940b903addbd779551569679f | Always when job runs |
|  | Inputs: `registry, username, password` |  |
| step-4 | elastic/oblt-actions/updatecli/run@v1 | Always when job runs |
|  | Inputs: `command, version-file` |  |
| step-5 | elastic/oblt-actions/slack/send@v1 | ${{ failure()  }} |
|  | Inputs: `bot-token, channel-id, message` |  |

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
- External action or reusable workflow: `elastic/oblt-actions/github/create-token@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/updatecli/run@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/updatecli-compose.yml`](../updatecli-compose.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `docker/login-action@dbcb813823bdd20940b903addbd779551569679f` (implementation not checked in this repository).
