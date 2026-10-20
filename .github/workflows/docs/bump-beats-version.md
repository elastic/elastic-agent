# Update Beats version

Checks active release branches for a newer Beats submodule revision and opens a branch-specific pull request when an update is available.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-beats-version.yml`](../bump-beats-version.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The Updatecli policy compares the latest commit on each active Beats branch with the version pinned in `go.mod`. The workflow comment notes that PR creation is handled separately because Updatecli does not correctly manage this submodule update.

## When it runs

Runs on a schedule or when manually dispatched. An active-branch filter supplies the matrix; the update job processes each branch independently with `fail-fast: false`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `filter` | Every run | None | Produces the active-branch matrix. |
| `update-beats` | Once per matrix branch | `filter` | Checks out the branch and runs Updatecli with the Beats policy, exports previous/new versions, then creates a PR. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Matrix branch name passed as `BRANCH_NAME`. |
| Permissions | Update job has `contents: write`, `id-token: write`, and `pull-requests: write`. |
| Outputs | PR targets the same matrix branch; the workflow posts a Slack alert on failure. |
| Secrets | `SLACK_BOT_TOKEN`; an ephemeral GitHub token is supplied to checkout and PR creation. |

## Operational notes

The local policy [`update-beats.yml`](../../../.ci/updatecli/update-beats.yml) invokes [`.ci/scripts/update-beats.sh`](../../../.ci/scripts/update-beats.sh), which updates the Beats submodule and aligns OTel dependencies when the Beats pin changes.

## Sources

- Workflow: [`bump-beats-version.yml`](../bump-beats-version.yml)
- Updatecli policy: [`update-beats.yml`](../../../.ci/updatecli/update-beats.yml)
- Helper: [`update-beats.sh`](../../../.ci/scripts/update-beats.sh)
