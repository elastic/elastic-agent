# Release Helm charts

Triggers the Helm chart Buildkite pipeline for published releases and supports a development snapshot run through manual dispatch.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`release-helm-charts.yml`](../release-helm-charts.yml) |
| Trigger | Manual dispatch or published release |

## Purpose

The workflow delegates Helm chart creation/publication to the `elastic-agent-helm-charts` Buildkite pipeline.

## When it runs

It listens for `workflow_dispatch` and published releases. The production job runs only for the published-release event and skips refs beginning with `8.16` or `8.17`. The manual-dispatch job runs when the event action is not `published`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `trigger-release` | Published release outside the excluded prefixes | None | Runs and waits for Buildkite using production settings; posts to Slack on failure. |
| `trigger-workflow` | Non-published dispatch event | None | Runs and waits for Buildkite using development snapshot settings. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Release ref is passed as the Buildkite branch. |
| Permissions | `contents: read`. |
| Outputs | Buildkite run result; production uses `SNAPSHOT=false` and `HELM_REPO_ENV=prod`, while manual runs use `SNAPSHOT=true` and `HELM_REPO_ENV=dev`. Both set `USE_PACKAGE_VERSION=false`. |
| Secrets | `BUILDKITE_TOKEN`; the production job also references `SLACK_BOT_TOKEN` on failure. |

## Operational notes

The Buildkite action is external; the checked-in pipeline is linked below.

## Sources

- Workflow: [`release-helm-charts.yml`](../release-helm-charts.yml)
- Checked-in pipeline definition: [`pipeline.elastic-agent-helm-charts.yml`](../../../.buildkite/pipeline.elastic-agent-helm-charts.yml)
