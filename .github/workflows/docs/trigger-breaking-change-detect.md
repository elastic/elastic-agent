# Detect breaking changes

Runs a scheduled agentic workflow that delegates breaking-change detection to the shared Elastic AI workflow.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-breaking-change-detect.yml`](../trigger-breaking-change-detect.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The caller invokes `gh-aw-breaking-change-detect.lock.yml` from `elastic/ai-github-actions` with repository setup commands.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is configured.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external breaking-change detector and installs the listed system libraries and Mage prerequisites. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | Failure-as-issue reporting is disabled by the caller. |

## Operational notes

The reusable workflow and detection logic are external and not checked into this repository.

## Sources

- Workflow: [`trigger-breaking-change-detect.yml`](../trigger-breaking-change-detect.yml)
