# Release Process

Quick reference for running elastic-agent releases using mage automation.

Feature-freeze and patch workflows are aligned with the former
[`elastic-agent.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/elastic-agent.mak)
/ vault-bot outputs, using the same grouped-PR and merge-timing label style as
[elastic/beats#51831](https://github.com/elastic/beats/pull/51831).

Release tooling lives under `dev-tools/mage/release/` in the root Go module.
Configuration is loaded through mage `Settings` (`ReleaseSettings`). Use the
`mage release:*` targets from the repository root.

## Prerequisites

```bash
go install github.com/magefile/mage@latest

export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
```

`CURRENT_RELEASE` must be plain `major.minor.patch` (no prerelease suffixes).

For feature freeze, `CURRENT_RELEASE` must already match `version/version.go` on
`BASE_BRANCH` (typically `main`) before the workflow runs.

For patch releases, `CURRENT_RELEASE` is the version to land (`NEW_VERSION`); the
release branch must already be at the previous patch on the same line.

## Feature freeze — `mage release:runMajorMinor`

Creates the release branch and **2 merge-ordered PRs**.

Example: `CURRENT_RELEASE=9.5.0` → branch `9.5`, next minor `9.6.0`.

| Step | Target | Branch | Merge label | What changes |
|------|--------|--------|-------------|--------------|
| 0 | — | `9.5` | — | Direct push from `main` |
| **PR-A** | `main` | `ff-prep-main-9.5.0` | `merge:1-ff-day` | Mergify backport + `version.go` + docs/manifests → next minor |
| **PR-B** | `9.5` | `ff-release-9.5.0` | `merge:2-after-branch` | version + docs + `mage update` |

Titles use `[Release <CURRENT_RELEASE>] …`.

Next-minor docs/manifests live in **PR-A** (agent historical vault-bot / `make check-ci` behavior). Beats keeps a separate after-images docs PR; agent does not.

Next-patch “Merge after the release” PRs are **not** opened here; they are owned by the patch workflow (`mage release:runPatch`).

After success (or in `DRY_RUN`), the workflow best-effort ensures the release
checklist issue `[RELEASE <CURRENT_RELEASE>] Instructions & Checklist` (linked to
https://github.com/elastic/ingest-dev/issues/8866). Re-run manually with
`mage release:ensureIssueTracker`.

```bash
export PROJECT_OWNER="your-user"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true
export CURRENT_RELEASE="9.5.0"

mage release:runMajorMinor

# Expect local branches:
#   9.5, ff-prep-main-9.5.0, ff-release-9.5.0
```

## Patch release — `mage release:runPatch`

Opens **1 PR**: post-release version bump to `CURRENT_RELEASE` (plus Helm/K8s
manifests). Docs stay off this path (aligned with ingest-dev#10200).

Example: branch `9.4` is at `9.4.3` → `CURRENT_RELEASE=9.4.4` (version to land).

| Step | Target | Branch | Merge label | What changes |
|------|--------|--------|-------------|--------------|
| **bump** | `9.4` | `update-version-9.4.4` | `merge:4-after-release` | `version.go` → CURRENT + Helm/K8s + `mage update` |

```bash
export PROJECT_OWNER="your-user"
export GITHUB_TOKEN=$(gh auth token)
export DRY_RUN=true
export CURRENT_RELEASE="9.4.4"

git fetch origin 9.4:9.4
mage release:runPatch

# Expect local branches:
#   update-version-9.4.4
```

## Individual Commands

```bash
mage release:runMajorMinor
mage release:runPatch
mage release:ensureIssueTracker
mage release:updateVersion 9.5.0
mage release:updateDocs 9.5.0
mage release:updatePatchDocs 9.4.1
mage release:updateMergify 9.5.0
mage -l | grep release
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CURRENT_RELEASE` | ✓ | - | FF: version on base; patch: version to land (`NEW_VERSION`) |
| `GITHUB_TOKEN` | ✓* | - | GitHub token (*not required in `DRY_RUN`) |
| `DRY_RUN` | | `false` | Preview mode (skip push/PR) |
| `BASE_BRANCH` | | `main` | Base branch for mainline PRs |
| `PROJECT_OWNER` | | `elastic` | GitHub owner |
| `PROJECT_REPO` | | `elastic-agent` | Repository name |
| `PROJECT_REVIEWERS` | | `elastic/elastic-agent-release` | Comma-separated reviewers |
| `GIT_AUTHOR_NAME` | | `elastic-machine` | Commit author |
| `GIT_AUTHOR_EMAIL` | | `infra-root+elasticmachine@elastic.co` | Commit email |

`LatestRelease`, `NextRelease`, and `ReleaseBranch` are inferred from
`CURRENT_RELEASE` (and GitHub releases for minor versions when needed). They are
not configurable via environment variables.

## Validation

```bash
cd dev-tools/mage/release && go test ./... -count=1
```

Discard local workflow artifacts after review with `git reset --hard HEAD` / branch cleanup.
