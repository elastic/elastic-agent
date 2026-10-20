# Update agent test versions

Updates package-version metadata on each active branch and opens a pull request when the generated version files change.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-agent-versions.yml`](../bump-agent-versions.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow refreshes the version data used by upgrade integration tests. The local helper calls Mage targets to generate the package version and requirements, then creates a branch and PR only when the tracked version files changed.

## When it runs

Runs on a schedule or when manually dispatched. Its filter job emits the active-branch matrix consumed by the update job.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `filter` | Every workflow run | None | Uses the external active-branches action to produce a filtered matrix. |
| `update_versions` | For each matrix branch | `filter` | Checks out the branch, installs Go and Mage, and runs the local update helper. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Active branches from the matrix. |
| Permissions | Update job has `contents: write`, `id-token: write`, and `pull-requests: write`. |
| Outputs | The helper writes the created PR URL to step output `pr`; Slack notifications are sent on failure and when a PR URL is produced. |
| Secrets | `SLACK_BOT_TOKEN`; the ephemeral token is minted through the external token action under the configured token policy. |

## Operational notes

The helper is [`.github/workflows/bump-agent-versions.sh`](../../../.github/workflows/bump-agent-versions.sh). It skips when neither version file changes and avoids creating another PR when an open `update-versions` PR already targets the branch.

## Sources

- Workflow: [`bump-agent-versions.yml`](../bump-agent-versions.yml)
- Helper: [`bump-agent-versions.sh`](../../../.github/workflows/bump-agent-versions.sh)
