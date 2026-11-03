# `buildkite-elastic-agent-integration-matrix`

This scheduled matrix packages the agent and runs the stateful integration matrix.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.integration-test-matrix.yml`](../pipeline.integration-test-matrix.yml), registered in [`catalog-info.yaml`](../../catalog-info.yaml) |
| Trigger | Weekly schedule on `main` (Thursday at 00:00); repository resource disables GitHub activity triggers. |

## Purpose

The pipeline provides a scheduled stateful integration run for the configured matrix. The pipeline resource describes it as running integration tests for supported platforms. The configuration itself packages test artifacts, then runs `integration:matrix`.

## When it runs

`catalog-info.yaml` defines a weekly `main` schedule (`0 0 * * 4`) and `trigger_mode: none`. No branch or PR filter is declared in the YAML.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Integration test packaging | Pipeline build | None declared | Runs [`integration-package.sh`](../scripts/steps/integration-package.sh) and uploads `build/distributions/**`. |
| Integration test matrix | After packaging | `package-it` | Downloads packages and runs `.buildkite/scripts/steps/integration_tests.sh stateful integration:matrix`; uploads test output and diagnostics. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `.package-version`, Buildkite metadata, and the matrix target passed to Mage. |
| Outputs | Package artifacts, `build/TEST-*`, and diagnostics. |
| Permissions | Google OIDC plugin is configured. |
| Secrets | No secret values are embedded in the pipeline source. |

## Operational notes

The integration runner enables package-version use, test cleanup, and snapshot packaging. The YAML does not enumerate the test matrix contents; those are defined by the Mage integration target.

## Sources and history

- Pipeline and registration: [`pipeline.integration-test-matrix.yml`](../pipeline.integration-test-matrix.yml), [`catalog-info.yaml`](../../catalog-info.yaml)
- Scripts: [`integration-package.sh`](../scripts/steps/integration-package.sh), [`integration_tests.sh`](../scripts/steps/integration_tests.sh)
- Relevant history: [`d68033a5a8`](https://github.com/elastic/elastic-agent/commit/d68033a5a8) updates artifact storage behavior for this pipeline.
