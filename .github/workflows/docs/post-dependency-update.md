# post-dependency-update

This GitHub Actions workflow coordinates **post-dependency-update** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/post-dependency-update.yml`](../post-dependency-update.yml) |
| Trigger | push: branches: dependabot/go_modules/**, renovate/*golang/** |

## Purpose

The workflow is named **post-dependency-update** and is configured to run the declared jobs: `update-notice`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `push: branches: dependabot/go_modules/**, renovate/*golang/**`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `update-notice` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `update-notice`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| step-2 | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| set up git user | elastic/oblt-actions/git/setup@v1 | Always when job runs |
|  | Inputs: `username, email` |  |
| Install mage | magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db | Always when job runs |
|  | Inputs: `version, install-only` |  |
| Update EDOT go.mod if necessary | `cd internal/edot && go mod tidy` | Always when job runs |
| check for modified edot go.mod | `if git diff --quiet HEAD -- internal/edot/go.mod; then` | Always when job runs |
| commit changed files | `git add internal/edot/go.mod internal/edot/go.sum` | steps.edot-check.outputs.modified == 'true' |
| Update archive-proxy go.mod if necessary | `cd wrapper/windows/archive-proxy && go mod tidy` | Always when job runs |
| check for modified archive-proxy go.mod | `if git diff --quiet HEAD -- wrapper/windows/archive-proxy/go.mod; then` | Always when job runs |
| commit archive-proxy changed files | `git add wrapper/windows/archive-proxy/go.mod wrapper/windows/archive-proxy/go.sum` | steps.archive-proxy-check.outputs.modified == 'true' |
| update NOTICE.txt and NOTICE-fips.txt | `mage notice` | Always when job runs |
| check for modified NOTICE.txt or NOTICE-fips.txt | `if git diff --quiet HEAD -- NOTICE*.txt; then` | Always when job runs |
| commit NOTICE.txt and/or NOTICE-fips.txt | `git add NOTICE*.txt` | steps.notice-check.outputs.modified == 'true' |
| update otel README.md | `mage otel:readme` | Always when job runs |
| check for modified otel README.md | `if git diff --quiet HEAD -- internal/edot/README.md; then` | Always when job runs |
| commit otel README.md | `git add internal/edot/README.md` | steps.otel-readme-check.outputs.modified == 'true' |
| regenerate mocks | `go tool mockery` | Always when job runs |
| format regenerated mocks | `mage fmt` | Always when job runs |
| check for modified mocks | `if git diff --quiet HEAD -- '*/mocks.go'; then` | Always when job runs |
| commit regenerated mocks | `git add '*/mocks.go'` | steps.mocks-check.outputs.modified == 'true' |
| Push added commits | `git push` | Always when job runs |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/oblt-actions/git/setup@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/post-dependency-update.yml`](../post-dependency-update.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
- External action or reusable workflow: `magefile/mage-action@a662bd8c29d8106879588cfff83b2faf6e6f59db` (implementation not checked in this repository).
