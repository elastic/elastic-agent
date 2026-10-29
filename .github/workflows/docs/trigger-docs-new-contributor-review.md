# Review documentation for new contributors

Runs a scheduled agentic patrol that delegates new-contributor documentation review to the shared Elastic AI workflow.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-docs-new-contributor-review.yml`](../trigger-docs-new-contributor-review.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The caller invokes the `gh-aw-newbie-contributor-patrol.lock.yml` reusable workflow with repository setup commands.

## When it runs

Runs on a schedule or when manually dispatched. No branch/path filter is configured.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every matching event | None | Calls the external documentation patrol workflow and installs the listed system libraries and Mage prerequisites. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `issues: write`, `pull-requests: read`. |
| Outputs | Failure-as-issue reporting is disabled by the caller. |

## Operational notes

The reusable workflow and patrol logic are external and not checked into this repository.

## Sources

- Workflow: [`trigger-docs-new-contributor-review.yml`](../trigger-docs-new-contributor-review.yml)
