# Generate release notes

Delegates release-note generation to the shared changelog-tool workflow when manually dispatched with a build-candidate SHA and version.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`release-notes.yml`](../release-notes.yml) |
| Trigger | Manual dispatch |

## Purpose

The caller configures the external release-note generator for Elastic Agent and supplies the release version and build-candidate commit.

## When it runs

It runs only through `workflow_dispatch`. Both `bc_commit_sha` and `version` are required string inputs.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `build-release-notes` | Every manual dispatch | None | Calls the reusable workflow in `elastic-agent-changelog-tool` with product, labels, release manager, and branching model. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `bc_commit_sha` and `version`. |
| Permissions | Job declares `contents: read` and `id-token: write`. |
| Outputs | Release-note generation behavior is owned by the external workflow. The caller passes the labels `docs`, `forwardport-main`, `release`, `skip-changelog`, and `Team:Docs`, and sets the branching model to `main`. |

## Operational notes

The reusable workflow is referenced at `@main`; its implementation is not checked into this repository and may change independently of this caller.

## Sources

- Workflow: [`release-notes.yml`](../release-notes.yml)
- Reusable workflow: [`generate-release-notes.yml`](https://github.com/elastic/elastic-agent-changelog-tool/blob/main/.github/workflows/generate-release-notes.yml)
