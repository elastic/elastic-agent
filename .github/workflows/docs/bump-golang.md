# Bump Go version

Checks for a newer Go release and opens a dependency pull request updating the repository's Go version declarations.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-golang.yml`](../bump-golang.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow applies the Updatecli Go policy, which selects the latest matching `golang-crossbuild` release and updates Go version files.

## When it runs

Runs on a schedule or when manually dispatched, with no branch/path filter. The schedule is configured in the workflow source.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `bump` | Every run | None | Checks out the repository and runs the Go Updatecli policy; posts to Slack if the job fails. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Job grants `contents: write` and `pull-requests: write`. |
| Outputs | Updatecli may open a dependency PR with labels from the policy. |
| Secrets | `GITHUB_TOKEN` for Updatecli and `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The policy [`updatecli-bump-golang.yml`](../../../.ci/updatecli/updatecli-bump-golang.yml) updates `.go-version`, the root and nested Go module versions, and `version/docs/version.asciidoc`. The workflow does not check out submodules.

## Sources

- Workflow: [`bump-golang.yml`](../bump-golang.yml)
- Updatecli policy: [`updatecli-bump-golang.yml`](../../../.ci/updatecli/updatecli-bump-golang.yml)
- SCM values: [`scm.yml`](../../../.ci/updatecli/values.d/scm.yml)
