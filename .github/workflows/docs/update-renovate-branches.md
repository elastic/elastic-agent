# Update Renovate base branches

Refreshes Renovate's branch targets from the active release-branch list and opens a pull request with the updated configuration.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`update-renovate-branches.yml`](../update-renovate-branches.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The inline script sets `baseBranchPatterns` from the active-branches action and rewrites the major-update rule so major updates are allowed on `main` and the latest branch of the previous major.

Rules the script is allowed to rewrite opt in by carrying the marker string `managed-by: update-renovate-branches` as an entry in their `description` array, so renaming a rule's human-readable text cannot silently detach it from the automation. Rules with a plain string `description` are never rewritten.

## When it runs

Runs on a schedule or when manually dispatched, with no branch/path filters.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `update` | Every matching event | None | Gets filtered active branches, updates `renovate.json`, opens a PR against `main`, and posts to Slack on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Branch matrix from the external active-branches action. |
| Permissions | Workflow grants `contents: read`; job grants `contents: write` and `pull-requests: write`. |
| Outputs | PR branch is `update-renovate-branches`, with automation labels. |
| Secrets | `GITHUB_TOKEN` for PR creation; `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The current Renovate rules are in [`renovate.json`](../../../renovate.json). The update job uses inline shell rather than a local helper script. When adding a rule whose `matchBaseBranches` should track the active release branches, give it an array `description` ending in the marker entry; otherwise leave the marker off and the rule is left alone.

## Sources

- Workflow: [`update-renovate-branches.yml`](../update-renovate-branches.yml)
- Renovate configuration: [`renovate.json`](../../../renovate.json)
