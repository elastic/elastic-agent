# bump-kube-stack-version

This GitHub Actions workflow coordinates **bump-kube-stack-version** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/bump-kube-stack-version.yml`](../bump-kube-stack-version.yml) |
| Trigger | workflow_dispatch; schedule |

## Purpose

The workflow is named **bump-kube-stack-version** and is configured to run the declared jobs: `bump`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `workflow_dispatch`
- `schedule`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `bump` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `bump`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| Install mage | magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db | Always when job runs |
|  | Inputs: `version, install-only` |  |
| step-3 | elastic/oblt-actions/updatecli/run@v1 | Always when job runs |
|  | Inputs: `command, version-file` |  |
| step-4 | elastic/oblt-actions/slack/send@v1 | ${{ failure()  }} |
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
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/updatecli/run@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/bump-kube-stack-version.yml`](../bump-kube-stack-version.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db` (implementation not checked in this repository).
