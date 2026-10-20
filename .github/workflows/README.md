# GitHub Actions workflows

This index covers all 49 checked-in `.github/workflows/*.yml` definitions. Each page documents the checked-in caller configuration and links to local dependencies where relevant.

## CI and documentation validation

- [Catalog metadata validation](docs/catalog-info.md)
- [Documentation build](docs/docs-build.md)
- [Documentation deployment](docs/docs-deploy.md)
- [Documentation preview cleanup](docs/docs-preview-cleanup.md)
- [Changelog fragment checks](docs/fragment-in-pr.md)
- [golangci-lint](docs/golangci-lint.md)
- [macOS unit tests](docs/macos-unit-tests.md)
- [Pre-commit checks](docs/pre-commit.md)
- [Documentation-generation structure validation](docs/validate-docs-structure.md)

## Dependency automation

- [Agent test-version updates](docs/bump-agent-versions.md)
- [Beats version updates](docs/bump-beats-version.md)
- [EDOT SDK image updates](docs/bump-edot-images.md)
- [Go version updates](docs/bump-golang.md)
- [Kube Stack chart updates](docs/bump-kube-stack-version.md)
- [OpenTelemetry dependency updates](docs/bump-otel-version.md)
- [VM image updates](docs/bump-vm-images.md)
- [Dependency-update follow-on changes](docs/post-dependency-update.md)
- [Renovate branch updates](docs/update-renovate-branches.md)
- [Composed Updatecli policies](docs/updatecli-compose.md)

## Release and publication

- [Manual Helm chart release](docs/release-helm-charts-manual.md)
- [Helm chart release](docs/release-helm-charts.md)
- [Release-note generation](docs/release-notes.md)
- [Generated documentation updates](docs/update-docs.md)

## Repository and infrastructure maintenance

- [Add labeled issues to the Platform Ingest project](docs/add-issues-to-ingest-board.md)
- [Backport to active branches](docs/backport-active.md)
- [Copy labels to Mergify backports](docs/mergify-labels-copier.md)
- [Buildkite flaky-test reporting](docs/report-buildkite-flaky-tests.md)
- [Serverless integration-test project](docs/serverless-project.md)

## Agentic audits and issue/PR assistance

- [Coordinator status-accuracy sweep](docs/sweep-coordinator-status-accuracy.md)
- [Fleet enrollment resilience sweep](docs/sweep-fleet-enrollment-resilience.md)
- [OTel Collector integration sweep](docs/sweep-otel-collector-integration.md)
- [Upgrade and rollback lifecycle sweep](docs/sweep-upgrade-lifecycle.md)
- [Breaking-change detection](docs/trigger-breaking-change-detect.md)
- [New-contributor documentation review](docs/trigger-docs-new-contributor-review.md)
- [Documentation patrol](docs/trigger-docs-patrol.md)
- [Duplicate issue detection](docs/trigger-duplicate-issue-detector.md)
- [Issue triage](docs/trigger-issue-triage.md)
- [AI assistance from issue comments](docs/trigger-mention-in-issue.md)
- [AI assistance from pull-request comments](docs/trigger-mention-in-pr.md)
- [PR workflow-failure investigation](docs/trigger-pr-actions-detective.md)
- [Automated PR review](docs/trigger-pr-review.md)
- [Stale-issue investigation](docs/trigger-stale-issues.md)
- [Text audit](docs/trigger-text-auditor.md)

## Observability Agentic Workflow event routing

- [Issue-comment events](docs/trigger-obs-aw-issue-comment.md)
- [Issue events](docs/trigger-obs-aw-issues.md)
- [Pull-request events](docs/trigger-obs-aw-pull-request.md)
- [Daily schedule profile](docs/trigger-obs-aw-schedule-daily.md)
- [Frequent schedule profile](docs/trigger-obs-aw-schedule-frequent.md)
- [Buildkite failure status events](docs/trigger-obs-aw-status.md)

## Source access gaps

Several callers use reusable workflows or actions maintained outside this repository, including `elastic/ai-github-actions`, `elastic/oblt-aw`, `elastic/oblt-actions`, `elastic/docs-actions`, and `elastic/elastic-agent-changelog-tool`. Their implementations are not checked in here; the per-workflow pages document only the local trigger, permissions, inputs, and configuration available in this checkout. No repository-local composite actions were found under `.github/actions/`, and none of the 49 checked-in workflow files defines a `workflow_call` reusable workflow.
