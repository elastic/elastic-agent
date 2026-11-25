# Add issue to Platform Ingest project

Adds issues labeled for Elastic Agent teams to the Platform Ingest GitHub project and sets their area.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`add-issues-to-ingest-board.yml`](../add-issues-to-ingest-board.yml) |
| Trigger | Issues labeled |

## Purpose

The workflow routes issues labeled `Team:Elastic-Agent-Data-Plane`, `Team:Elastic-Agent-Control-Plane`, or `Team:Elastic-Agent` into the configured Platform Ingest project and assigns the Elastic Agent area.

## When it runs

It starts for an `issues:labeled` event. Both GraphQL steps run only when the new label matches one of the three team labels above.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `add_to_project` | Matching team label | None | Adds the issue to the project and returns its item ID. |
| `set_elastic_agent_area` | Matching team label | `add_to_project` | Sets the project's area field to the Elastic Agent option. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Issue node ID and the event's label; project and field IDs are configured in the workflow. |
| Permissions | Workflow-level `contents: none`; the GraphQL token is supplied by `PROJECT_ASSIGNER_TOKEN`. |
| Outputs | The first mutation's project item ID feeds the second mutation. |

## Operational notes

Both mutations use `octokit/graphql-action`. Their GraphQL operation details are inline; no local action implementation is referenced.

## Sources

- Workflow: [`add-issues-to-ingest-board.yml`](../add-issues-to-ingest-board.yml)
