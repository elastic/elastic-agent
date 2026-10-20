# update-beats

This GitHub Actions workflow coordinates **update-beats** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/bump-beats-version.yml`](../bump-beats-version.yml) |
| Trigger | workflow_dispatch; schedule |

## Purpose

The workflow is named **update-beats** and is configured to run the declared jobs: `filter`, `update-beats`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `workflow_dispatch`
- `schedule`

## Execution flow

```mermaid
flowchart TD
  filter --> update_beats
```

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `filter` | Always when triggered | None declared | ubuntu-slim |
| `update-beats` | Always when triggered | `[filter]` | ubuntu-latest |

### Steps

#### `filter`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | elastic/oblt-actions/elastic/active-branches@v1 | Always when job runs |
|  | Inputs: `filter-branches` |  |
#### `update-beats`

| Step | Action or command | Condition |
| --- | --- | --- |
| Create ephemeral GitHub token | elastic/oblt-actions/github/create-token@v1 | Always when job runs |
|  | Inputs: `token-policy` |  |
| step-2 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules, ref, token` |  |
| Set up Go | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| Install mage | magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db | Always when job runs |
|  | Inputs: `version, install-only` |  |
| Run Updatecli in Apply mode | elastic/oblt-actions/updatecli/run@v1 | Always when job runs |
|  | Inputs: `command, version-file` |  |
| Export beats versions to environment variables | `echo BEATS_PREVIOUS_VERSION=$(cat /tmp/.beats-previous-version) >> "$GITHUB_ENV"` | Always when job runs |
| Create Pull Request | peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1 | Always when job runs |
|  | Inputs: `token, commit-message, title, body, branch, base, delete-branch, labels` |  |
| step-8 | elastic/oblt-actions/slack/send@v1 | ${{ failure() }} |
|  | Inputs: `bot-token, channel-id, message` |  |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | Workflow variables: JOB_URL |
| Outputs | Job outputs: `filter`: matrix |
| Permissions | `{contents: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/oblt-actions/elastic/active-branches@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/github/create-token@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/updatecli/run@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/bump-beats-version.yml`](../bump-beats-version.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
- External action or reusable workflow: `magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db` (implementation not checked in this repository).
- External action or reusable workflow: `peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1` (implementation not checked in this repository).
