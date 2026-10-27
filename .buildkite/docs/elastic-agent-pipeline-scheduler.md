# `elastic-agent-pipeline-scheduler`

This scheduled pipeline discovers active release branches and triggers the requested Elastic Agent Buildkite pipeline for each branch.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`trigger_pipelines.yml`](../trigger_pipelines.yml), registered in [`catalog-info.yaml`](../../catalog-info.yaml) |
| Trigger | Daily schedule on `main`; the configured schedule sets `PIPELINES_TO_TRIGGER=elastic-agent-extended-testing`. |

## Purpose

The scheduler creates regular extended integration runs across active branches. The checked-in generator downloads the active-branch list, optionally excludes configured branches, and uploads one trigger step per pipeline/branch pair.

## When it runs

The repository resource defines a daily schedule on `main` (`@daily`), sets a 240-minute maximum timeout, and disables GitHub activity triggers. In the current schedule, only `elastic-agent-extended-testing` is selected.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Generate trigger steps | Scheduled build | None declared | Runs [`trigger-pipeline-generate-steps.sh`](../scripts/trigger-pipeline-generate-steps.sh), which fetches active branches, filters exclusions, writes generated steps, and uploads them to Buildkite. |
| Per-branch pipeline triggers | Generated dynamically | Generated from `PIPELINES_TO_TRIGGER` and active branches | Triggers each requested pipeline on each eligible branch with a scheduled-build message. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `PIPELINES_TO_TRIGGER` is required; `EXCLUDE_BRANCHES` is optional. Both are comma-separated values. |
| Outputs | Dynamically uploaded Buildkite trigger steps. |
| Permissions | Buildkite agent pipeline-upload access is required. |
| Secrets | No secret values are referenced in the checked-in definition. |

## Operational notes

The external active-branch list is read from the Elastic release API's public S3 endpoint. Failure to retrieve it stops generation. The source does not include Buildkite's live schedule object; the schedule recorded here is from `catalog-info.yaml`.

## Sources and history

- Pipeline and schedule: [`trigger_pipelines.yml`](../trigger_pipelines.yml), [`catalog-info.yaml`](../../catalog-info.yaml)
- Generator: [`trigger-pipeline-generate-steps.sh`](../scripts/trigger-pipeline-generate-steps.sh)
- Relevant history: [`0fe58539a7`](https://github.com/elastic/elastic-agent/commit/0fe58539a7) adds scheduled extended integration tests for active branches.
