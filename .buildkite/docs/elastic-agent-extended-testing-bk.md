# `elastic-agent-extended-testing-bk`

This registered pipeline uses the extended integration matrix defined in `bk.integration.pipeline.yml`.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`bk.integration.pipeline.yml`](../bk.integration.pipeline.yml), registered as `elastic-agent-extended-testing-bk` in [`catalog-info.yaml`](../../catalog-info.yaml) |
| Trigger | The catalog resource sets `trigger_mode: none`; the YAML has PR, source-filtered, and scheduled-tier conditions. |

## Purpose

This is a separate registered Buildkite entry using the same test definition that is included in the combined `elastic-agent-extended-testing` pipeline. It does not define packaging steps of its own, while its jobs reference artifacts from `packaging-*` steps; whether those are supplied in a particular external run depends on the Buildkite build configuration.

## When it runs

The checked-in resource disables GitHub activity triggers. Within the YAML, tier 1 groups run on PRs, tier 2 groups use `if_changed` filters for CI/build/test inputs, and tier 3 groups run for scheduled builds or builds triggered by `elastic-agent-pipeline-scheduler`. External trigger configuration is not present here.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Custom ECH tests | Pipeline build | Container/Linux packages | Runs ECH integration tests using the current commit's cloud image. |
| ESS provisioning | Pipeline build | None declared | Creates the shared test stack and prepares Fleet packages. |
| Windows/Linux groups | PR, filtered changes, or schedule by tier | ESS and platform package artifacts | Executes integration variants across OS, package type, sudo mode, and test tier. |
| Kubernetes/OpenShift groups | PR, filtered changes, or schedule by tier | ESS and amd64 container package | Runs configured Kubernetes and MicroShift version/image matrices. |
| Serverless test group | Pipeline build | Platform package artifacts | Runs serverless integration tests on Windows and Linux. |
| Cleanup and reports | End of integration flow | Test groups; failures allowed | Cleans shared/retry clusters and aggregates JUnit reports. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | Buildkite branch/PR/schedule metadata, `.package-version`, and configured matrix values. |
| Outputs | Integration XML/JSON/HTML, diagnostics, Kubernetes logs, and test annotations. |
| Permissions | Google OIDC, `oblt-cli`, Vault-backed GitHub access, and external ESS/test services are used. |
| Secrets | Values are external; the source references Google secret-manager and Vault plugins. |

## Operational notes

Automatic retries reuse the initial ESS stack, while manual retries can create another. A cleanup step also scans metadata for retry clusters that may have been orphaned. The paired packaging configuration is documented with [`elastic-agent-extended-testing`](elastic-agent-extended-testing.md).

## Sources and history

- Pipeline and registration: [`bk.integration.pipeline.yml`](../bk.integration.pipeline.yml), [`catalog-info.yaml`](../../catalog-info.yaml)
- Scripts: [`ess_start_oblt-cli.sh`](../scripts/steps/ess_start_oblt-cli.sh), [`integration_tests_oblt-cli.sh`](../scripts/steps/integration_tests_oblt-cli.sh), [`ess_cleanup_all.sh`](../scripts/steps/ess_cleanup_all.sh)
- Relevant history: [`6055fc33f8`](https://github.com/elastic/elastic-agent/commit/6055fc33f8) records changes to the shared integration packaging and upload flow.
