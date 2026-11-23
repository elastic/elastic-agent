# Bump OpenTelemetry versions

Updates OpenTelemetry Collector core and contrib dependencies on `main` and `8.19` when manually dispatched.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`bump-otel-version.yml`](../bump-otel-version.yml) |
| Trigger | Manual dispatch |

## Purpose

The workflow updates OTel dependency versions through Updatecli. The source comments explain that the schedule is disabled because these updates are handled manually due to upstream dependencies such as Beats and Elastic components.

## When it runs

Only `workflow_dispatch` is enabled. The update job has a fixed matrix for `main` and `8.19`, with `fail-fast: false`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `update-otel` | Once per configured branch | None | Checks out submodules, installs Go and Mage, then applies the OTel Updatecli policy; sends Slack notification on failure. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Branch matrix and SCM values. |
| Permissions | Job grants `contents: write` and `pull-requests: write`. |
| Outputs | Updatecli policy may create a PR for each branch with changed dependencies. |
| Secrets | `GITHUB_TOKEN` for Updatecli and `SLACK_BOT_TOKEN` for failure notification. |

## Operational notes

The policy [`update-otel.yml`](../../../.ci/updatecli/update-otel.yml) calls [`.ci/scripts/update-otel.sh`](../../../.ci/scripts/update-otel.sh), which updates core and contrib modules, runs module tidy, regenerates related artifacts, and creates a changelog fragment.

## Sources

- Workflow: [`bump-otel-version.yml`](../bump-otel-version.yml)
- Updatecli policy: [`update-otel.yml`](../../../.ci/updatecli/update-otel.yml)
- Helper: [`update-otel.sh`](../../../.ci/scripts/update-otel.sh)
