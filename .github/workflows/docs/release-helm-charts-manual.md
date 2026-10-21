# Manually release Helm charts

Dispatches the `elastic-agent-helm-charts` Buildkite pipeline with operator-supplied branch, commit, and repository environment.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`release-helm-charts-manual.yml`](../release-helm-charts-manual.yml) |
| Trigger | Manual dispatch |

## Purpose

This is the manual release path for the Helm chart pipeline, with explicit inputs for the source branch, commit, and `dev` or `prod` repository environment.

## When it runs

It runs only by `workflow_dispatch`. All three inputs (`branch`, `commit`, `repo-env`) are required; `repo-env` is a choice between `dev` and `prod`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `trigger-release` | Every manual dispatch | None | Runs the Buildkite pipeline and waits for completion; sends a Slack alert if the job fails. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `branch`, `commit`, and `repo-env`. |
| Permissions | `contents: read`; job uses the `helmcharts` environment. |
| Outputs | Buildkite run result; `SNAPSHOT` is true for `dev`, and `HELM_REPO_ENV` is the selected value. |
| Secrets | `BUILDKITE_TOKEN` and, on failure, `SLACK_BOT_TOKEN`. |

## Operational notes

The Buildkite action targets the `elastic-agent-helm-charts` pipeline and sets `USE_PACKAGE_VERSION=false`. Its implementation is external.

## Sources

- Workflow: [`release-helm-charts-manual.yml`](../release-helm-charts-manual.yml)
- Checked-in pipeline definition: [`pipeline.elastic-agent-helm-charts.yml`](../../../.buildkite/pipeline.elastic-agent-helm-charts.yml)
