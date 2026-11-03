# Bump VM image versions

Checks active release branches for a newer CI VM image version and opens pull requests with the Buildkite image references updated.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-vm-images.yml`](../bump-vm-images.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow applies an Updatecli policy to update image versions in checked-in Buildkite pipeline YAML files.

## When it runs

Runs on a schedule or when manually dispatched. An external active-branches action provides a filtered branch matrix; the update job runs once for each branch with `fail-fast: false`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `filter` | Every run | None | Generates active branch matrix. |
| `bump` | For each matrix branch | `filter` | Checks out the target branch, applies the VM image policy, and sends a Slack alert on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Matrix branch passed as `BRANCH_NAME`. |
| Permissions | Update job grants `contents: write` and `pull-requests: write`. |
| Outputs | The Updatecli policy may open a PR for the branch. |
| Secrets | `GITHUB_TOKEN` for Updatecli; `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The policy [`updatecli-bump-vm-images.yml`](../../../.ci/updatecli/updatecli-bump-vm-images.yml) reads the latest image date and updates GCP/AWS and Azure image strings in `.buildkite/*.yml`.

## Sources

- Workflow: [`bump-vm-images.yml`](../bump-vm-images.yml)
- Updatecli policy: [`updatecli-bump-vm-images.yml`](../../../.ci/updatecli/updatecli-bump-vm-images.yml)
- SCM values: [`scm.yml`](../../../.ci/updatecli/values.d/scm.yml)
