# Backport to active branches

Starts the external active-branch backport action for merged pull requests carrying an active-backport label.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`backport-active.yml`](../backport-active.yml) |
| Trigger | Pull requests closed or labeled on `main` |

## Purpose

The workflow delegates backporting to `elastic/oblt-actions` after a pull request is merged and has a `backport-active-*` label.

## When it runs

It listens to `pull_request_target` events `closed` and `labeled` on the `main` base branch. The job requires `merged == true`; for a close event, the PR must already have a matching label, while a label event must add a label whose name starts with `backport-active-`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `backport` | The merged-PR and label condition is true | None | Runs `elastic/oblt-actions/github/backport-active@v1`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `pull-requests: write`, `contents: read`. |
| Outputs | Backport behavior is delegated to the external action. |

## Operational notes

The implementation of the external action is not present in this repository, so its branch-selection details are not documented here.

## Sources

- Workflow: [`backport-active.yml`](../backport-active.yml)
