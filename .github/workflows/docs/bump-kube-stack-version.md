# Bump OpenTelemetry Kube Stack version

Checks the latest OpenTelemetry Kube Stack Helm chart and updates its tested version and local integration-test data.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-kube-stack-version.yml`](../bump-kube-stack-version.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow runs the repository's Updatecli policy, which compares the upstream chart release with the version used by Kubernetes integration tests and updates chart test data.

## When it runs

Runs on a schedule or when manually dispatched. No branch or path filter is configured.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `bump` | Every run | None | Checks out submodules, installs Mage, and applies the Kube Stack Updatecli policy; posts a Slack alert on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Job grants `contents: write` and `pull-requests: write`. |
| Outputs | Updatecli may open a PR with the labels specified by the policy. |
| Secrets | `GITHUB_TOKEN` for Updatecli and `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The local policy [`updatecli-bump-kube-stack.yml`](../../../.ci/updatecli/updatecli-bump-kube-stack.yml) updates `testing/integration/k8s/k8s.go` and then invokes [`.ci/scripts/update-integration-testdata.sh`](../../../.ci/scripts/update-integration-testdata.sh).

## Sources

- Workflow: [`bump-kube-stack-version.yml`](../bump-kube-stack-version.yml)
- Updatecli policy: [`updatecli-bump-kube-stack.yml`](../../../.ci/updatecli/updatecli-bump-kube-stack.yml)
- Helper: [`update-integration-testdata.sh`](../../../.ci/scripts/update-integration-testdata.sh)
