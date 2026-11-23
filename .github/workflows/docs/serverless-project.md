# Create serverless integration-test project

Creates a daily serverless test project, performs a smoke request, and rotates the associated test-cluster secrets.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`serverless-project.yml`](../serverless-project.yml) |
| Trigger | Manual dispatch or schedule |

## Purpose

The workflow provisions a serverless Elastic project for integration testing, checks Elasticsearch access, and writes the resulting cluster credentials to named Google Cloud Secret Manager secrets.

## When it runs

Runs on a schedule or when manually dispatched. The workflow has no event filters or inputs; the created cluster name is suffixed with the current weekday.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| `create-serverless` | Every matching event | None | Mints an app token, creates the serverless project, obtains credentials, smoke-tests Elasticsearch, authenticates to the CI GCP project, then rotates six named secrets. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Permissions | Workflow grants `contents: read`; job grants `id-token: write`. |
| Outputs | Cluster name and credentials are consumed by later steps; no uploaded artifact is declared. |
| Secrets | `OBS_AUTOMATION_APP_ID`, `OBS_AUTOMATION_APP_PEM`, and `SLACK_BOT_TOKEN` on failure. |

## Operational notes

This workflow changes cloud resources and secrets. It was inspected for documentation only and was not run. Cluster creation, authentication, and credential actions are maintained in external repositories.

## Sources

- Workflow: [`serverless-project.yml`](../serverless-project.yml)
