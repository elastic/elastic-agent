# Agentless quality-gate entry pipeline

This pipeline validates the Agentless service image and uses the quality-gate seedling runner to execute tests for the selected environment.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml) |
| Trigger | The source describes this as the quality-gate entry point invoked during automated promotion; the remote trigger settings are not checked into this repository. |

## Purpose

The entry pipeline validates that the service image is multi-architecture, then launches the environment-specific test snippet through the quality-gate seedling image. The definition points to the QA, staging, and production snippets under `.buildkite/`.

## When it runs

`ENVIRONMENT` is required from the caller. The file does not define a branch filter. Its comment describes automatic invocation after a new version is rolled out to a cloud stage. On `main`, a failed build sends a Slack notification to the channel in `TEAM_CHANNEL`.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Validate service image | Every build | None declared | Runs [`validate-agentless-docker-image.sh`](../scripts/steps/validate-agentless-docker-image.sh) and requires amd64 and arm64. |
| Seedling test trigger | After validation succeeds | Wait step following image validation | Runs [`run-agentless-tests.sh`](../scripts/steps/run-agentless-tests.sh), which resolves the deployed controller SHA from `serverless-gitops` and calls the seedling image's environment test target. |
| Environment snippet | Seedling dispatch | Environment selection | The seedling image runs `make -C /agent run-environment-tests`; the mapping from `ENVIRONMENT` to the checked-in QA, staging, and production snippets is external to this repository. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Required `ENVIRONMENT`; `TEAM_CHANNEL` defaults to `#agentless-alerts`. |
| Outputs | Image validation result and environment quality-gate test result. |
| Permissions | Vault Docker login is used to inspect the internal service image; the seedling agent runs the test selection. |
| Secrets | The Docker-login plugin references `elastic_docker_registry`; credential values are external. |

## Operational notes

The test runner clones or updates the `elastic/serverless-gitops` repository to read the deployed service version, installs `yq`, then runs `make -C /agent run-environment-tests`. That repository and the seedling image's implementation—including its exact environment-to-snippet mapping—are external to this checkout.

## Sources and history

- Pipeline: [`pipeline.agentless-tests.yaml`](../pipeline.agentless-tests.yaml)
- Scripts and environment snippets: [`run-agentless-tests.sh`](../scripts/steps/run-agentless-tests.sh), [`validate-agentless-docker-image.sh`](../scripts/steps/validate-agentless-docker-image.sh), [`pipeline.tests-qa.yaml`](../pipeline.tests-qa.yaml), [`pipeline.tests-staging.yaml`](../pipeline.tests-staging.yaml), [`pipeline.tests-production.yaml`](../pipeline.tests-production.yaml)
- Relevant history: [`2812c6fb6c`](https://github.com/elastic/elastic-agent/commit/2812c6fb6c) adds the agentless release/test configuration; [`a1f8d82a1a`](https://github.com/elastic/elastic-agent/commit/a1f8d82a1a) adds image validation and changes the pipeline to stop before testing if validation fails.
