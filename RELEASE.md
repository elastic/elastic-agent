# Release Process

Quick reference for running elastic-agent releases using mage automation.

Feature-freeze and patch workflows are aligned with the former
[`elastic-agent.mak`](https://github.com/elastic/ingest-dev/blob/main/release_scripts/elastic-agent.mak)
/ vault-bot outputs, using the same grouped-PR and merge-timing label style as
[elastic/beats#51831](https://github.com/elastic/beats/pull/51831).

Release tooling lives in a **nested Go module** (`dev-tools/mage/release/`). Root
mage targets invoke `go run -C dev-tools/mage/release ./cmd/agent-release …` so
`go-git` / `go-github` stay out of the root `go.mod` and `NOTICE.txt`.

## Prerequisites

```bash
go install github.com/magefile/mage@latest

export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
```

`CURRENT_RELEASE` must be plain `major.minor.patch` (no prerelease suffixes).

For feature freeze, `CURRENT_RELEASE` must already match `version/version.go` on
`BASE_BRANCH` (typically `main`) before the workflow runs.

For patch releases, `CURRENT_RELEASE` must already match `version/version.go`
on the release branch (set by the previous cycle's next-patch PR).

## Feature freeze — `mage release:runMajorMinor`

Creates the release branch and **3 merge-ordered PRs**.

Example: `CURRENT_RELEASE=9.5.0` → branch `9.5`, next minor `9.6.0`, next patch `9.5.1`.

| Step | Target | Branch | Merge label | What changes |
|------|--------|--------|-------------|--------------|
| 0 | — | `9.5` | — | Direct push from `main` |
| **PR-A** | `main` | `ff-prep-main-9.5.0` | `merge:1-ff-day` | Mergify backport + `version.go` + docs/manifests → next minor |
| **PR-B** | `9.5` | `ff-release-9.5.0` | `merge:2-after-branch` | version + docs + `mage update` |
| **PR-D** | `9.5` | `ff-prep-next-patch-9.5.1` | `merge:4-after-release` | `version.go` + Helm/K8s manifests → next patch + `mage update` |

Titles use `[Release <CURRENT_RELEASE>] …`.

Next-minor docs/manifests live in **PR-A** (agent historical vault-bot / `make check-ci` behavior). Beats keeps a separate after-images docs PR; agent does not.

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
#   9.5, ff-prep-main-9.5.0, ff-release-9.5.0,
#   ff-prep-next-patch-9.5.1
```

## Patch release — `mage release:runPatch`

Creates **2 merge-ordered PRs** on the release branch.

Example: branch `9.4` already has `version/version.go` at `9.4.3` →
`CURRENT_RELEASE=9.4.3`, next patch `9.4.4`.

| Step | Target | Branch | Merge label | What changes |
|------|--------|--------|-------------|--------------|
| **PR-A** | `9.4` | `patch-release-9.4.3` | `merge:1-before-build` | docs + `:stack-version:` only (no `version.go` bump) |
| **PR-B** | `9.4` | `ff-prep-next-patch-9.4.4` | `merge:4-after-release` | next patch `version.go` + Helm/K8s manifests + `mage update` |

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
| `CURRENT_RELEASE` | ✓ | - | Version to release (e.g., `9.5.0`) |
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
