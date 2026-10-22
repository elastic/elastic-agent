# `elastic-agent-helm-charts`

This pipeline packages an Elastic Agent Helm chart, uploads it to the configured GCS bucket, and dynamically triggers unified-release publication.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.elastic-agent-helm-charts.yml`](../pipeline.elastic-agent-helm-charts.yml), registered in [`catalog-info.yaml`](../../catalog-info.yaml) |
| Trigger | Repository resource sets `trigger_mode: none`; the checked-in YAML has no branch or event filter. |

## Purpose

The pipeline creates a Helm chart archive and passes its URL and target environment to `unified-release-publish-helm-charts`. Its config defaults to dev snapshots unless callers override the inputs. The history records `SNAPSHOT=true` as the Mage default.

## When it runs

No trigger is declared in the YAML. `catalog-info.yaml` registers `elastic-agent-helm-charts` with GitHub activity triggering disabled. The pipeline is also triggered by the binary DRA pipeline for non-main snapshot builds.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Create Helm chart | Pipeline build | None declared | Runs [`helm-charts.sh`](../scripts/steps/helm-charts.sh), which calls `mage helm:package`, uploads the archive to `elastic-agent-helm-chart` in GCS, and uploads a trigger step. |
| Publish chart | Dynamically uploaded after chart creation | Chart archive and URL | Triggers `unified-release-publish-helm-charts` with `CHARTS_URL` and `HELM_REPO_ENV`. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `HELM_REPO_ENV` defaults to `dev`; `SNAPSHOT` defaults to `true`. |
| Outputs | `elastic-agent-*.tgz` archive, uploaded chart object, and downstream publication build. |
| Permissions | Google OIDC authenticates to GCP for upload. |
| Secrets | No secret values appear in the pipeline source. |

## Operational notes

The helper exits if `SNAPSHOT=true` and `HELM_REPO_ENV=prod`. The publication step is generated dynamically by [`trigger-publish-helm-charts.sh`](../scripts/steps/trigger-publish-helm-charts.sh). The remote publication pipeline is outside this repository.

## Sources and history

- Pipeline and registration: [`pipeline.elastic-agent-helm-charts.yml`](../pipeline.elastic-agent-helm-charts.yml), [`catalog-info.yaml`](../../catalog-info.yaml)
- Scripts: [`helm-charts.sh`](../scripts/steps/helm-charts.sh), [`trigger-publish-helm-charts.sh`](../scripts/steps/trigger-publish-helm-charts.sh)
- Relevant history: [`ff4469b9eb`](https://github.com/elastic/elastic-agent/commit/ff4469b9eb) sets the Helm packaging default to `SNAPSHOT=true`.
