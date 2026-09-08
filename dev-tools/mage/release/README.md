# Elastic Agent Release Automation

Operator and developer guide for Elastic Agent release automation using mage.

Release managers should start with the root
[`RELEASE.md`](../../../RELEASE.md) (what runs when, what PRs are produced,
merge order). This file covers how to configure, run, and debug the mage
targets.

## Overview

This package provides release automation for Elastic Agent via mage. It is part
of the root Go module; configuration is loaded through
[`dev-tools/mage` Settings](../settings.go) (`ReleaseSettings`) alongside other
mage env settings. Root mage targets call package functions directly.

**Workflows supported:**
1. **Major/Minor Release (feature-freeze)** — Creates release branch + 3 grouped PRs
2. **Patch Release** — Creates 2 grouped PRs on the release branch (docs before build; next-patch version + Helm/K8s manifests after release)

Release notes are handled separately via `.github/workflows/release-notes.yml`.

## Prerequisites

- **Go** — version in `.go-version`
- **Git**
- **Mage** — `go install github.com/magefile/mage@latest`
- **GitHub Token** — `repo` scope when not in `DRY_RUN`

## Quick Start

### Feature freeze (`runMajorMinor`) — 3 PRs

```bash
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
export DRY_RUN=true

mage release:runMajorMinor
```

### Patch (`runPatch`) — 2 PRs

```bash
export CURRENT_RELEASE="9.4.3"
export DRY_RUN=true

git fetch origin 9.4:9.4
mage release:runPatch
```

## Available Commands

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

## Configuration

Release env vars are loaded in `LoadSettings()` into `Settings.Release`
(`ReleaseSettings` in `dev-tools/mage/release_settings.go`). `CURRENT_RELEASE`
is optional for general mage targets; release workflows call `RequireRelease()`.

| Variable | Description | Example |
|----------|-------------|---------|
| `CURRENT_RELEASE` | Version to release | `9.5.0` |
| `GITHUB_TOKEN` | GitHub personal access token | `ghp_...` |
| `DRY_RUN` | Preview mode (no push/PR) | `true` |
| `BASE_BRANCH` | Base branch for mainline PRs | `main` |
| `PROJECT_OWNER` | GitHub repository owner | `elastic` |
| `PROJECT_REPO` | GitHub repository name | `elastic-agent` |
| `PROJECT_REVIEWERS` | Comma-separated reviewers | `elastic/elastic-agent-release` |

`LatestRelease`, `NextRelease`, and `ReleaseBranch` are always inferred from
`CURRENT_RELEASE` (and GitHub releases for minor versions). They are not
configurable via environment variables.

### Version file

Workflows read and update `version/version.go` (`const defaultBeatVersion = "…"`).
Feature freeze requires `CURRENT_RELEASE` to match that file on `BASE_BRANCH`.
Patch releases require it to match on the release branch.

### EnsureIssueTracker

Creates or updates `[RELEASE <version>] Instructions & Checklist`, linking the
global tracker (https://github.com/elastic/ingest-dev/issues/8866) and Elastic
Agent PRs labeled `release` that mention the version.

```bash
export CURRENT_RELEASE="9.4.1"
export GITHUB_TOKEN="ghp_your_token"
mage release:ensureIssueTracker
```

Also runs automatically (best-effort, non-blocking) at the end of `runMajorMinor`
and `runPatch`.

## DRY_RUN Mode

Executes file updates, branch creation, and validation locally. Skips push, PR
creation, and GitHub API calls (except validation that needs a token when not in
dry-run).

## Testing

```bash
go test ./dev-tools/mage/ ./dev-tools/mage/release/ -count=1
```

## Package layout

| File | Purpose |
|------|---------|
| `../release_settings.go` | `ReleaseSettings` and env loading via `LoadSettings` |
| `config.go` | GitHub latest-release resolution and validation helpers |
| `release.go` | File updates (`UpdateVersion`, `UpdateDocs`, `ReadAgentVersion`, …) |
| `mergify.go` | `.mergify.yml` backport rule updates |
| `workflows.go` | Orchestration (`RunMajorMinorRelease`, `RunPatchRelease`) |
| `issue.go` | Release checklist issue tracker |
| `git.go` | Git operations (includes submodule sync for agent) |
| `github.go` | Pull request creation, label ensure, related-PR lookup |
