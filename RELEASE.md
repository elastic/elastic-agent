# Release Process

Quick reference for running elastic-agent releases using mage automation.

Feature-freeze and patch workflows are aligned with the former
[`elastic-agent.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/elastic-agent.mak)
/ vault-bot outputs, using the same grouped-PR and merge-timing label style as
[elastic/beats#51831](https://github.com/elastic/beats/pull/51831).

## Prerequisites

```bash
go install github.com/magefile/mage@latest

export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
```

`CURRENT_RELEASE` must be plain `major.minor.patch` (no prerelease suffixes).

## Feature freeze — `mage release:runMajorMinor`

Creates the release branch and **4 merge-ordered PRs**.

Example: `CURRENT_RELEASE=9.5.0` → branch `9.5`, next minor `9.6.0`, next patch `9.5.1`.

| Step | Target | Branch | Merge label | Former outputs | What changes |
|------|--------|--------|-------------|----------------|--------------|
| 0 | — | `9.5` | — | branch push | Direct push from `main` |
| **PR-A** | `main` | `ff-prep-main-9.5.0` | `merge:1-ff-day` | bump-version + add-backport | `.mergify.yml` + `version.go` → next minor + manifests |
| **PR-B** | `9.5` | `ff-release-9.5.0` | `merge:2-after-branch` | release-branch content | version + docs + `mage update` |
| **PR-C** | `main` | `ff-prep-main-docs-9.6.0` | `merge:3-after-images` | update-dev-docs | docs with `RELEASE=main` |
| **PR-D** | `9.5` | `ff-prep-next-patch-9.5.1` | `merge:4-after-release` | update-version-next | `version.go` → next patch (+ `mage update`) |

```bash
export PROJECT_OWNER="your-user"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true
export CURRENT_RELEASE="9.5.0"

mage release:runMajorMinor

# Expect local branches:
#   9.5, ff-prep-main-9.5.0, ff-release-9.5.0,
#   ff-prep-main-docs-9.6.0, ff-prep-next-patch-9.5.1
```

## Patch release — `mage release:runPatch`

Creates **2 merge-ordered PRs** on the release branch (one PR per merge step; no test-env PR).

Example: `CURRENT_RELEASE=9.4.3` → branch `9.4`, next patch `9.4.4`.

| Step | Target | Branch | Merge label | Former outputs | What changes |
|------|--------|--------|-------------|----------------|--------------|
| **PR-A** | `9.4` | `patch-release-9.4.3` | `merge:1-before-build` | update-version + update-docs-version | `version.go` + docs/manifests |
| **PR-B** | `9.4` | `ff-prep-next-patch-9.4.4` | `merge:4-after-release` | update-version-next | next patch version (+ `mage update`) |

Labels on PR-A: `docs`, `in progress`, `release`, `Team:Automation`, `skip-changelog`, `merge:1-before-build`.
PR-B: `release`, `Team:Automation`, `skip-changelog`, `merge:4-after-release`.

```bash
export PROJECT_OWNER="your-user"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true
export CURRENT_RELEASE="9.4.3"

git fetch origin 9.4:9.4
mage release:runPatch

# Expect local branches:
#   patch-release-9.4.3, ff-prep-next-patch-9.4.4
```

## Individual Commands

```bash
mage release:updateVersion 9.5.0
mage release:updateDocs 9.5.0
mage release:updatePatchDocs 9.4.1
mage release:updateMergify 9.5.0
mage -l | grep release
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CURRENT_RELEASE` | ✓ | - | Version to release (e.g., `9.5.0`) |
| `GITHUB_TOKEN` | ✓* | - | GitHub token (*not required in `DRY_RUN`) |
| `DRY_RUN` | | `false` | Preview mode (skip push/PR) |
| `BASE_BRANCH` | | `main` | Base branch for mainline PRs |
| `RELEASE_BRANCH` | | inferred | Release branch (`major.minor`) |
| `NEXT_RELEASE` | | inferred | Next patch (`patch+1`) |
| `NEXT_PROJECT_MINOR_VERSION` | | inferred | Next minor (`minor+1.0`) |
| `LATEST_RELEASE` | | inferred | Previous patch (optional) |
| `PROJECT_OWNER` | | `elastic` | GitHub owner |
| `PROJECT_REPO` | | `elastic-agent` | Repository name |

## Validation

```bash
go test ./dev-tools/mage/release/... -count=1
```

Discard local workflow artifacts after review with `git reset --hard HEAD` / branch cleanup.
