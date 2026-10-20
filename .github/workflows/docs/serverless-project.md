# serverless-project

This GitHub Actions workflow coordinates **serverless-project** from the checked-in definition.

## At a glance

| | |
| --- | --- |
| Platform | GitHub Actions |
| Source | [`.github/workflows/serverless-project.yml`](../serverless-project.yml) |
| Trigger | workflow_dispatch; schedule |

## Purpose

The workflow is named **serverless-project** and is configured to run the declared jobs: `create-serverless`. Its operational purpose is defined by those jobs and their source steps; the checked-in file does not state additional rationale.

## When it runs

Runs on a schedule; consult the workflow source for the current scheduler configuration.
The configured trigger events and filters are:

- `workflow_dispatch`
- `schedule`

## Execution flow

| Job | Runs when | Depends on | Runner or reusable workflow |
| --- | --- | --- | --- |
| `create-serverless` | Always when triggered | None declared | ubuntu-latest |

### Steps

#### `create-serverless`

| Step | Action or command | Condition |
| --- | --- | --- |
| Get token | actions/create-github-app-token@v3 | Always when job runs |
|  | Inputs: `app-id, private-key, permission-checks, permission-contents, permission-pull-requests, repositories` |  |
| step-2 | elastic/oblt-actions/git/setup@v1 | Always when job runs |
|  | Inputs: `github-token` |  |
| Get day of the week | `echo "day=$(date +'%a' \| tr '[:upper:]' '[:lower:]')" >> $GITHUB_OUTPUT` | Always when job runs |
| step-4 | elastic/oblt-actions/oblt-cli/cluster-create-custom@v1 | Always when job runs |
|  | Inputs: `username, template, parameters, cluster-name-prefix, github-token, gitops, wait` |  |
| step-5 | elastic/oblt-actions/google/auth@v1 | Always when job runs |
| step-6 | elastic/oblt-actions/oblt-cli/cluster-credentials@v1 | Always when job runs |
|  | Inputs: `cluster-name, github-token` |  |
| Smoke test | `curl -X GET ${ELASTICSEARCH_HOST}/_cat/indices?v -u ${ELASTICSEARCH_USERNAME}:${ELASTICSEARCH_PASSWORD}` | Always when job runs |
| step-8 | elastic/oblt-actions/google/auth@v1 | Always when job runs |
|  | Inputs: `project-number, project-id` |  |
| Set up Cloud SDK | google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db | Always when job runs |
| Rotate GCSM secrets | `echo -n "${ELASTICSEARCH_HOST}" \| gcloud secrets versions add "${PREFIX}-elasticsearch-hostname" --data-file=- --quiet --project "${GCP_PROJECT}"` | Always when job runs |
| step-11 | elastic/oblt-actions/slack/send@v1 | ${{ failure()  }} |
|  | Inputs: `bot-token, channel-id, message` |  |

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
- External action or reusable workflow: `elastic/oblt-actions/google/auth@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/oblt-cli/cluster-create-custom@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/oblt-cli/cluster-credentials@v1` (implementation not checked in this repository).
- External action or reusable workflow: `elastic/oblt-actions/slack/send@v1` (implementation not checked in this repository).

- Workflow: [`.github/workflows/serverless-project.yml`](../serverless-project.yml)
- External action or reusable workflow: `actions/create-github-app-token@v3` (implementation not checked in this repository).
- External action or reusable workflow: `google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db` (implementation not checked in this repository).
