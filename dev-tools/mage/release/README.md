# Elastic Agent Release Automation

This directory contains the mage-based release automation system for elastic-agent.
It follows the same package layout and grouped-PR / merge-label model as
[elastic/beats#51831](https://github.com/elastic/beats/pull/51831), covering the
former [`elastic-agent.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/elastic-agent.mak)
outputs.

| File | Purpose |
|------|---------|
| `config.go` | Environment-based `ReleaseConfig` and version inference |
| `release.go` | File updates (`UpdateVersion`, `UpdateDocs`, `UpdateDocsWithOptions`, `UpdatePatchDocs`) |
| `mergify.go` | `.mergify.yml` backport rule updates |
| `workflows.go` | Orchestration (`RunMajorMinorRelease`, `RunPatchRelease`) |
| `git.go` | Git operations (`EnsureBranchFrom`, `CommitAll`, …) |
| `github.go` | Pull request creation, label ensure, idempotent reuse |

## Quick Start

### Feature freeze (`runMajorMinor`) — 4 PRs

```bash
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
export DRY_RUN=true

mage release:runMajorMinor
```

Creates release branch + PR-A/B/C/D with `merge:1-ff-day` … `merge:4-after-release`.
See [RELEASE.md](../../../RELEASE.md) for the full mapping table.

### Patch (`runPatch`) — 2 PRs

```bash
export CURRENT_RELEASE="9.4.3"
export RELEASE_BRANCH="9.4"
export DRY_RUN=true

git fetch origin 9.4:9.4
mage release:runPatch
```

Creates `patch-release-*` and next-patch PRs with `merge:1-before-build` / `merge:4-after-release`.

### Prerequisites

- **Go** — version in `.go-version`
- **Git**
- **Mage** — `go install github.com/magefile/mage@latest`
- **GitHub Token** — `repo` scope when not in `DRY_RUN`

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CURRENT_RELEASE` | Version to release | `9.5.0` |
| `GITHUB_TOKEN` | GitHub personal access token | `ghp_...` |
| `DRY_RUN` | Preview mode (no push/PR) | `true` |
| `BASE_BRANCH` | Base branch for mainline PRs | `main` |
| `PROJECT_OWNER` | GitHub repository owner | `elastic` |
| `PROJECT_REPO` | GitHub repository name | `elastic-agent` |

## Available Commands

```bash
mage release:runMajorMinor
mage release:runPatch
mage release:updateVersion 9.5.0
mage release:updateDocs 9.5.0
mage release:updatePatchDocs 9.4.1
mage release:updateMergify 9.5.0
mage release:prepareMajorMinor
mage release:createBranch
mage release:createPR
```

## Dry Run Mode

```bash
export DRY_RUN=true
export CURRENT_RELEASE="9.5.0"
mage release:runMajorMinor
```

Updates local files and creates local branches; does not push or open PRs.

## Idempotency

Re-runs reuse existing branches, skip empty commits, and reuse open PRs while re-applying labels.

## Testing

```bash
go test ./dev-tools/mage/release/... -count=1
```
