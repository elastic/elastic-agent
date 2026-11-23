# Copy labels to Mergify backports

Copies eligible labels from a pull request to an automatically created Mergify backport pull request.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`mergify-labels-copier.yml`](../mergify-labels-copier.yml) |
| Trigger | Pull request opened |

## Purpose

The workflow delegates label copying to `elastic/oblt-actions` for pull requests whose head branch uses the `mergify/bp/` prefix.

## When it runs

It listens to `pull_request:opened`; the job condition restricts execution to `mergify/bp/` head branches.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `mergify-backport-labels-copier` | Head branch starts with `mergify/bp/` | None | Runs the external labels-copier action and excludes labels matching the configured backport pattern. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`; job-level `pull-requests: write` and `repository-projects: read`. |
| Outputs | Label changes are performed by the external action. |

## Operational notes

The action implementation is external and is not checked into this repository.

## Sources

- Workflow: [`mergify-labels-copier.yml`](../mergify-labels-copier.yml)
