# Validate documentation-generation structure

Checks that required local source files for generated EDOT documentation are present when relevant files change in a pull request.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`validate-docs-structure.yml`](../validate-docs-structure.yml) |
| Trigger | Pull request changing EDOT or documentation-generator paths |

## Purpose

The workflow runs the `mage check:docsFiles` target to ensure the documentation generator's required source files exist.

## When it runs

It runs for pull requests changing `internal/edot/**`, `docs/scripts/update-docs/**`, or the workflow file itself.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `validate-structure` | Matching pull request | None | Checks out submodules, installs Go from `go.mod`, installs Mage, and runs `mage check:docsFiles`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | `contents: read`. |
| Outputs | Check result; no artifact is declared. |

## Operational notes

The Mage target checks `go.mod`, `internal/edot/components.yml`, and `internal/edot/samples/linux/gateway.yml`. The checker is implemented in `magefile.go`.

## Sources

- Workflow: [`validate-docs-structure.yml`](../validate-docs-structure.yml)
- Source checker: [`magefile.go`](../../../magefile.go)
- Generator: [`update-components-docs.py`](../../../docs/scripts/update-docs/update-components-docs.py)
