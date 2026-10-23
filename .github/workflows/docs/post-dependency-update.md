# Apply dependency-update follow-on changes

Regenerates module metadata, notices, documentation, and mocks on dependency-update branches, then pushes any generated commits.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`post-dependency-update.yml`](../post-dependency-update.yml) |
| Trigger | Push to Dependabot Go-module or Renovate Go branches |

## Purpose

The workflow comment states that Go dependency updates require refreshed `NOTICE.txt` and `NOTICE-fips.txt`; the remaining steps update related generated files on the same dependency branch.

## When it runs

It runs on pushes to `dependabot/go_modules/**` or `renovate/*golang/**`. Individual generated-file commits are conditional on whether their corresponding files changed.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `update-notice` | Matching branch push | None | Tidies EDOT and archive-proxy modules, regenerates notices and EDOT README, regenerates/formats mocks, commits changed files, and pushes the resulting commits. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Workflow grants `contents: read`; the job overrides with `contents: write`. |
| Outputs | Generated commits are pushed to the triggering branch. |

## Operational notes

This workflow has write access and pushes directly to the dependency-update branch. It is documentation of the configured automation; it was not run as part of this documentation work.

## Sources

- Workflow: [`post-dependency-update.yml`](../post-dependency-update.yml)
