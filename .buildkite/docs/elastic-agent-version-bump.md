# `elastic-agent-version-bump`

This main-branch Buildkite pipeline runs the configured minor or patch version-bump Mage target and reports its status to Slack.

## At a glance

| | |
| --- | --- |
| Platform | Buildkite |
| Source | [`pipeline.version-bump.yml`](../pipeline.version-bump.yml), registered in [`catalog-info.yaml`](../../catalog-info.yaml) |
| Trigger | `main` only; repository resource disables branch and PR builds from GitHub activity. |

## Purpose

The pipeline automates minor or patch release-version updates. Its current definition includes start/success/failure/blocked notifications, workflow-specific bump steps, and an explicit blocked placeholder before a dependent branch step.

## When it runs

The repository resource restricts the pipeline to `main`, disables branch and PR builds, and disables GitHub-activity triggering. Pipeline steps use `WORKFLOW=minor` or `WORKFLOW=patch` to select the Mage target. Notifications are scoped to `main` and release branches, or to a blocked build.

## Execution flow

| Job or step | Runs when | Depends on | What it does |
| --- | --- | --- | --- |
| Start notification | Main or release branch | None declared | Emits a Slack message that the requested version bump started. |
| Bump version minor | `WORKFLOW=minor` | None declared | Runs `make mage` and `mage release:runMajorMinor` with `CURRENT_RELEASE=NEW_VERSION`. |
| Bump version patch | `WORKFLOW=patch` | None declared | Runs `make mage` and `mage release:runPatch` with `CURRENT_RELEASE=NEW_VERSION` and `BASE_BRANCH=BRANCH`. |
| Placeholder blocked step | Pipeline build | None declared | Blocks for a human unblock and displays `NEW_VERSION`, `BRANCH`, and `WORKFLOW`. |
| Create branch for version bump | After the blocked step is unblocked | `block-get-dra-artifacts` | Current command is `echo "Placeholder"`; no branch operation is implemented in this YAML. |

## Inputs, outputs, and access

| Item | Details |
| --- | --- |
| Inputs | `NEW_VERSION`, `BRANCH`, and `WORKFLOW` are supplied by the caller. |
| Outputs | Mage version-bump changes; Slack notifications on configured build states. |
| Permissions | Uses the Vault GitHub token plugin for version-bump operations; runner has custom global hooks. |
| Secrets | GitHub token is supplied by the Vault plugin; its value is not present in the repository. |

## Operational notes

The bump steps have a 60-minute timeout. The branch step is still a placeholder, and the blocked step text refers to the prior DRA-artifact process; documentation reflects the checked-in YAML rather than inferring future behavior.

## Sources and history

- Pipeline and registration: [`pipeline.version-bump.yml`](../pipeline.version-bump.yml), [`catalog-info.yaml`](../../catalog-info.yaml)
- Relevant history: [`70328b49fe`](https://github.com/elastic/elastic-agent/commit/70328b49fe) removes an older block/placeholder flow and adjusts Slack notifications; [`06f87824aa`](https://github.com/elastic/elastic-agent/commit/06f87824aa) adds feature-freeze automation support.
