# Validate changelog fragments in pull requests

Checks eligible pull requests for a changelog fragment and validates its syntax with the changelog tool.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`fragment-in-pr.yml`](../fragment-in-pr.yml) |
| Trigger | Pull request opened, reopened, synchronized, labeled, or unlabeled |

## Purpose

The workflow uses the Elastic Agent changelog tool to check that a PR has a fragment and that fragments build for the current agent version.

## When it runs

The job skips PRs labeled `skip-changelog` or `backport`, and heads under `mergify/merge-queue/`. Other pull request events in the trigger list run the job.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `fragments` | PR passes the label and head-ref conditions | None | Checks out submodules, installs the latest changelog tool, checks for a fragment, extracts the version, and validates fragment syntax. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Pull request repository name and number; agent version is read from `version/version.go`. |
| Permissions | `contents: read`. |
| Outputs | The job reports the PR fragment checks; no artifacts are declared. |

## Operational notes

The changelog tool is installed by the workflow; its implementation is external to this repository.

## Sources

- Workflow: [`fragment-in-pr.yml`](../fragment-in-pr.yml)
- Version source: [`version/version.go`](../../../version/version.go)
