# Triage new issues

Invokes the shared issue-triage workflow when an issue is opened.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`trigger-issue-triage.yml`](../trigger-issue-triage.yml) |
| Trigger | Issue opened |

## Purpose

The caller delegates new-issue triage to `gh-aw-issue-triage.lock.yml` in `elastic/ai-github-actions`.

## When it runs

It listens to `issues:opened`, with no additional job condition or branch filter.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `run` | Every issue-opened event | None | Calls the external triage workflow and installs the listed system libraries and Mage prerequisites. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `actions: read`, `contents: read`, `copilot-requests: write`, `discussions: write`, `issues: write`, `pull-requests: write`. |
| Outputs | Triage results are produced by the external workflow; failure-as-issue reporting is disabled. |

## Operational notes

The reusable workflow implementation is not checked in here.

## Sources

- Workflow: [`trigger-issue-triage.yml`](../trigger-issue-triage.yml)
