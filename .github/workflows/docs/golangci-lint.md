# Run golangci-lint

Runs golangci-lint across three operating systems and two build-tag sets for Go changes.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`golangci-lint.yml`](../golangci-lint.yml) |
| Trigger | Push to supported branches or pull request with matching paths |

## Purpose

The workflow lints changed Go-related code and establishes a base cache on branch pushes to speed up pull-request runs. The two tag sets cover the default build and selected custom build constraints.

## When it runs

Pushes to `main`, `8.19`, or `9.*` and pull requests run only when Go files, module files, lint configuration/version, or this workflow changes. The matrix combines Ubuntu, macOS, and Windows with `default` and `define` build-tag sets.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `golangci` | Each OS/tag-set matrix entry | None | Checks out submodules, installs Go, and runs the pinned golangci-lint action with whole-file linting and a 60-minute timeout. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Go toolchain from `.go-version`; linter version from `.golangci-lint-version`; matrix build tags. |
| Permissions | `contents: read`, `pull-requests: read`. |
| Outputs | Lint annotations; the action is configured to show only new issues on pull requests. |

## Operational notes

The workflow notes that a third `local` build-tag variant is intentionally not included in the matrix.

## Sources

- Workflow: [`golangci-lint.yml`](../golangci-lint.yml)
- Linter configuration: [`../../../.golangci.yml`](../../../.golangci.yml)
- Linter version: [`../../../.golangci-lint-version`](../../../.golangci-lint-version)
