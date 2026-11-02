# Buildkite pipeline documentation

These pages describe the Buildkite definitions and supporting configuration checked into this repository. `catalog-info.yaml` supplies registered pipeline names, branch filters, and schedules where available; `.buildkite/pull-requests.json` documents the repository's PR-trigger integration. Neither file proves that live Buildkite settings match the checkout.

## Pipeline pages

| Pipeline or configuration | Documentation |
| --- | --- |
| Primary CI: `elastic-agent` | [Primary pipeline](docs/elastic-agent.md) |
| Extended tests: `elastic-agent-extended-testing` | [Packaging and integration tiers](docs/elastic-agent-extended-testing.md) |
| Extended tests: `elastic-agent-extended-testing-bk` | [Independent registration of the shared test definition](docs/elastic-agent-extended-testing-bk.md) |
| Dynamically uploaded FIPS integration configuration | [FIPS extended integration steps](docs/bk-integration-fips.md) |
| Full packages: `elastic-agent-package` | [Package and DRA publishing](docs/elastic-agent-package.md) |
| Core binaries: `elastic-agent-binary-dra` | [Core snapshot and staging DRA](docs/elastic-agent-binary-dra.md) |
| Helm charts: `elastic-agent-helm-charts` | [Chart packaging and publication](docs/elastic-agent-helm-charts.md) |
| Scheduled integration matrix: `buildkite-elastic-agent-integration-matrix` | [Integration test matrix](docs/buildkite-elastic-agent-integration-matrix.md) |
| Version automation: `elastic-agent-version-bump` | [Version bump pipeline](docs/elastic-agent-version-bump.md) |
| Active-branch scheduler: `elastic-agent-pipeline-scheduler` | [Scheduled pipeline triggers](docs/elastic-agent-pipeline-scheduler.md) |
| Agentless service release | [Serverless image build and promotion](docs/agentless-serverless-release.md) |
| Agentless quality-gate entry point | [Environment test dispatcher](docs/pipeline-agentless-tests.md) |
| Agentless QA checks | [QA quality-gate snippet](docs/pipeline-tests-qa.md) |
| Agentless staging checks | [Staging quality-gate snippet](docs/pipeline-tests-staging.md) |
| Agentless production checks | [Production quality-gate snippet](docs/pipeline-tests-production.md) |

## Source gaps

- `catalog-info.yaml` references `.buildkite/macos.integration.pipeline.yml` and `.buildkite/macos.integration.scheduler.yml`, but neither file exists in this checkout. Their runtime definitions could not be checked, so they are not documented as repository pipeline pages.
- The downstream `serverless-quality-gates`, `unified-release-*`, and agentless GitOps pipeline definitions are outside this repository. Pages describe only the local trigger contracts.
- Buildkite's live schedules, provider settings, and runtime-generated steps are not independently verified against the Buildkite service; this index describes checked-in YAML and repository metadata only.
