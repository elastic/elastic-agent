# Bump EDOT SDK images

Checks for newer EDOT SDK image releases and opens a dependency pull request when configured image references change.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-edot-images.yml`](../bump-edot-images.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow runs the repository's Updatecli policy for the .NET, Java, Node.js, Python, and Go instrumentation images used by the EDOT Kubernetes Helm chart values.

## When it runs

Runs on a schedule or when manually dispatched. There are no branch or path filters in the workflow definition.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `bump` | Every run | None | Checks out the repository and applies the EDOT image Updatecli policy; sends a Slack notification on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Job grants `contents: write` and `pull-requests: write`. |
| Outputs | Updatecli may open a dependency PR; the policy defines its labels and title. |
| Secrets | `GITHUB_TOKEN` for Updatecli and `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The policy [`updatecli-bump-edot.yml`](../../../.ci/updatecli/updatecli-bump-edot.yml) reads upstream releases and updates both EDOT Helm values files. It is invoked with [`values.d/scm.yml`](../../../.ci/updatecli/values.d/scm.yml); submodules are not checked out.

## Sources

- Workflow: [`bump-edot-images.yml`](../bump-edot-images.yml)
- Updatecli policy: [`updatecli-bump-edot.yml`](../../../.ci/updatecli/updatecli-bump-edot.yml)
- SCM values: [`scm.yml`](../../../.ci/updatecli/values.d/scm.yml)
