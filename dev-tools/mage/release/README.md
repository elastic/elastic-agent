# Elastic Agent Release Automation

Operator and developer guide for Elastic Agent release automation using mage.

Release managers should start with the root
[`RELEASE.md`](../../../RELEASE.md) (what runs when, what PRs are produced,
merge order). This file covers how to configure, run, and debug the mage
targets.

## Overview

This package provides release automation for Elastic Agent via mage.

It lives in a **nested Go module** (`dev-tools/mage/release/go.mod`) so tooling
dependencies (`go-git`, `go-github`, and their transitive tree) stay out of the
root `go.mod` and `NOTICE.txt`. Root mage targets invoke
`go run -C ./dev-tools/mage/release ./cmd/agent-release …`.

**Workflows supported:**
1. **Major/Minor Release (feature-freeze)** — Creates release branch + 4 grouped PRs
2. **Patch Release** — Creates 2 grouped PRs on the release branch (docs before build; next-patch version after release)

Release notes are handled separately via `.github/workflows/release-notes.yml`.

## Prerequisites

- **Go** — version in `.go-version`
- **Git**
- **Mage** — `go install github.com/magefile/mage@latest`
- **GitHub Token** — `repo` scope when not in `DRY_RUN`

## Quick Start

### Feature freeze (`runMajorMinor`) — 4 PRs

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
cd dev-tools/mage/release
go test ./... -count=1
```

## CLI (optional)

For local debugging from the repo root:

```bash
go run -C ./dev-tools/mage/release ./cmd/agent-release help
ELASTIC_AGENT_REPO_ROOT=$PWD go run -C ./dev-tools/mage/release ./cmd/agent-release run-major-minor
```

`ELASTIC_AGENT_REPO_ROOT` is set automatically by mage when using `mage release:*`.

## Package layout

| File | Purpose |
|------|---------|
| `config.go` | Environment-based `ReleaseConfig` and version inference |
| `release.go` | File updates (`UpdateVersion`, `UpdateDocs`, `ReadAgentVersion`, …) |
| `mergify.go` | `.mergify.yml` backport rule updates |
| `workflows.go` | Orchestration (`RunMajorMinorRelease`, `RunPatchRelease`) |
| `issue.go` | Release checklist issue tracker |
| `git.go` | Git operations (includes submodule sync for agent) |
| `github.go` | Pull request creation, label ensure, related-PR lookup |
| `cmd/agent-release/` | Nested-module CLI invoked by root mage |
