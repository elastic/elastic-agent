# fragment-in-pr

This GitHub Actions workflow coordinates **fragment-in-pr** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/fragment-in-pr.yml`](../fragment-in-pr.yml) |
| Trigger | pull_request: types: labeled, unlabeled, opened, reopened, synchronize |

## Purpose

The workflow is named **fragment-in-pr** and is configured to run the declared jobs: `fragments`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `pull_request: types: labeled, unlabeled, opened, reopened, synchronize`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `fragments` | !contains(github.event.pull_request.labels.*.name, 'skip-changelog') && !contains(github.event.pull_request.labels.*.name, 'backport') && !startsWith(github.head_ref, 'mergify/merge-queue/') | None declared | ubuntu-latest |

### Steps

#### `fragments`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | actions/checkout@v7 | Always when job runs |
|  | Inputs: `submodules` |  |
| step-2 | actions/setup-go@v7 | Always when job runs |
|  | Inputs: `go-version-file` |  |
| check pr-has-fragment | `GOBIN=$PWD/bin go install github.com/elastic/elastic-agent-changelog-tool@latest` | Always when job runs |
| get elasti-agent version | `gv=$(awk '$0 ~ /[0-9]+\.[0-9]+\.[0-9]+/ {print $4}' version/version.go)` | Always when job runs |
| check fragment-syntax | `./bin/elastic-agent-changelog-tool build --version ${{steps.agent-version.outputs.agent-version}} --owner elastic --repo elastic-agent` | Always when job runs |

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

Referenced source gaps:

- `./bin/elastic-agent-changelog-tool` is referenced by the workflow but is not present in this checkout.

## Sources

- Workflow: [`.github/workflows/fragment-in-pr.yml`](../fragment-in-pr.yml)
- External action or reusable workflow: `actions/checkout@v7` (implementation not checked in this repository).
- External action or reusable workflow: `actions/setup-go@v7` (implementation not checked in this repository).
