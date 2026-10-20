# Add issue to Platform Ingest project

This GitHub Actions workflow coordinates **Add issue to Platform Ingest project** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/add-issues-to-ingest-board.yml`](../add-issues-to-ingest-board.yml) |
| Trigger | issues: types: labeled |

## Purpose

The workflow is named **Add issue to Platform Ingest project** and is configured to run the declared jobs: `add_to_ingest_project`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

The configured trigger events and filters are:

- `issues: types: labeled`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `add_to_ingest_project` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `add_to_ingest_project`

| Step | Action or command | Condition |
| --- | --- | --- |
| step-1 | octokit/graphql-action@v2.x | github.event.label.name == env.DATA_PLANE_LABEL \|\| github.event.label.name == env.CONTROL_PLANE_LABEL \|\| github.event.label.name == env.ELASTIC_AGENT_LABEL |
|  | Inputs: `query, project_id, content_id` |  |
| step-2 | octokit/graphql-action@v2.x | github.event.label.name == env.DATA_PLANE_LABEL \|\| github.event.label.name == env.CONTROL_PLANE_LABEL \|\| github.event.label.name == env.ELASTIC_AGENT_LABEL |
|  | Inputs: `query, item_id, project_id, area_field_id, area_id` |  |

The tables above summarize the complete job and step structure; action implementations referenced outside this repository are not expanded.

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | No workflow inputs are declared. |
| Environment | Workflow variables: INGEST_PROJECT_ID, DATA_PLANE_LABEL, CONTROL_PLANE_LABEL, ELASTIC_AGENT_LABEL, AREA_FIELD_ID, ELASTIC_AGENT_OPTION_ID |
| Outputs | No job outputs are declared; artifacts, caches, and step outputs are defined by individual steps where present. |
| Permissions | `{contents: none}` |
| Deployment environments | No job deployment environment is declared. |

## Operational notes

This page documents checked-in configuration only. It does not prove successful runs or that remote action and reusable-workflow implementations match their referenced revisions.

## Sources

- Workflow: [`.github/workflows/add-issues-to-ingest-board.yml`](../add-issues-to-ingest-board.yml)
- External action or reusable workflow: `octokit/graphql-action@v2.x` (implementation not checked in this repository).
