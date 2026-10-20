# Generate release notes

This GitHub Actions workflow coordinates **Generate release notes** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/release-notes.yml`](../release-notes.yml) |
| Trigger | workflow_dispatch: inputs: bc_commit_sha: description: Commit SHA for the build candidate; workflow_dispatch: inputs: bc_commit_sha: type: string; workflow_dispatch: inputs: bc_commit_sha: required: True; workflow_dispatch: inputs: version: description: Version to be released (for example, `9.2.1`); workflow_dispatch: inputs: version: type: string; workflow_dispatch: inputs: version: required: True |

## Purpose

The workflow is named **Generate release notes** and is configured to run the declared jobs: `build-release-notes`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `workflow_dispatch: inputs: bc_commit_sha: description: Commit SHA for the build candidate`
- `workflow_dispatch: inputs: bc_commit_sha: type: string`
- `workflow_dispatch: inputs: bc_commit_sha: required: True`
- `workflow_dispatch: inputs: version: description: Version to be released (for example, `9.2.1`)`
- `workflow_dispatch: inputs: version: type: string`
- `workflow_dispatch: inputs: version: required: True`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `build-release-notes` | Always when triggered | None declared | elastic/elastic-agent-changelog-tool/.github/workflows/generate-release-notes.yml@main |

### Steps

#### `build-release-notes`

| Step | Action or command | Condition |
| --- | --- | --- |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `workflow_dispatch` input names: bc_commit_sha, version |
| Environment | No workflow-level environment variables are declared. |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: read}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources
- External action or reusable workflow: `elastic/elastic-agent-changelog-tool/.github/workflows/generate-release-notes.yml@main` (implementation not checked in this repository).

- Workflow: [`.github/workflows/release-notes.yml`](../release-notes.yml)
