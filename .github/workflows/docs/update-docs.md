# Update generated documentation after releases

Checks whether a release is the latest stable tag and, if so, generates component documentation from that release and opens a documentation pull request.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`update-docs.yml`](../update-docs.yml) |
| Trigger | Published release, manual dispatch, or schedule |

## Purpose

The workflow maintains generated EDOT component tables, OCB configuration, gateway tables, and sample links. The caller's comments explain that generation uses `main` as the working tree while release data is read from the release tag.

## When it runs

Runs on a schedule, for published releases, or when manually dispatched. The first job uses the release tag for release events or the latest stable semantic tag otherwise; the generation job proceeds only when that version is the latest stable tag.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `check-latest` | Every run | None | Determines the version and whether it is the latest stable tag. |
| `update-docs` | Latest-version check is true | `check-latest` | Checks out `main` with submodules and history, installs Python requirements, runs the generator, skips if the version branch exists, otherwise opens a PR. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Release tag when triggered by a release; otherwise tags fetched from the upstream repository. |
| Permissions | Workflow grants `contents: read`; update job grants `contents: write`, `pull-requests: write`, and `issues: write`. |
| Outputs | A version-specific `update-docs-*` branch and pull request unless that branch already exists. |
| Secrets | `GITHUB_TOKEN` for pull request creation. |

## Operational notes

The generator [`update-components-docs.py`](../../../docs/scripts/update-docs/update-components-docs.py) reads tagged module/component metadata and updates marked documentation sections using local Jinja templates. It also updates component `since` data in `internal/edot/components.yml`.

## Sources

- Workflow: [`update-docs.yml`](../update-docs.yml)
- Generator: [`update-components-docs.py`](../../../docs/scripts/update-docs/update-components-docs.py)
- Generator requirements: [`requirements.txt`](../../../docs/scripts/update-docs/requirements.txt)
- Generator guide: [`README.md`](../../../docs/scripts/update-docs/README.md)
- Component metadata: [`components.yml`](../../../internal/edot/components.yml)
- Documentation mappings: [`component-docs.yml`](../../../docs/reference/edot-collector/component-docs.yml)
- Templates: [`templates/`](../../../docs/scripts/update-docs/templates/)
