# Release Process

Quick reference for running elastic-agent releases using mage automation.

## Prerequisites

```bash
# Install mage (if not already installed)
go install github.com/magefile/mage@latest

# Configure environment
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
```

## Major/Minor Release

### Automated (Recommended)

```bash
# Dry run first
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_..."
export DRY_RUN=true
mage release:runMajorMinor

# Review changes, then run for real
export DRY_RUN=false
mage release:runMajorMinor
```

### Manual Steps

```bash
# 1. Start from a clean working tree (automation checks out main)
export CURRENT_RELEASE="9.5.0"

# 2. Create release branch from main, update files, and commit
mage release:createBranch

# 3. Push branch and create pull request
mage release:createPR
```

## Patch Release

### Automated (Recommended)

```bash
# Dry run first
export CURRENT_RELEASE="9.4.1"
export LATEST_RELEASE="9.4.0"
export RELEASE_BRANCH="9.4"
export GITHUB_TOKEN="ghp_..."
export DRY_RUN=true
mage release:runPatch

# Review changes, then run for real
export DRY_RUN=false
mage release:runPatch
```

Creates two PRs into the release branch:
- `update-version-next-9.4.1` — bumps `version/version.go` and deployment manifests ([example](https://github.com/elastic/elastic-agent/pull/14423))
- `update-docs-version-9.4.1` — updates `:stack-version:` in `version/docs/version.asciidoc` ([example](https://github.com/elastic/elastic-agent/pull/15000))

### Manual Steps

```bash
# PR 1: version bump
export CURRENT_RELEASE="9.4.1"
export RELEASE_BRANCH="9.4"
git fetch origin 9.4
git checkout -b update-version-next-9.4.1 origin/9.4
mage release:updateVersion 9.4.1
mage release:updateDocs 9.4.1
git add -A && git commit -m "update version to 9.4.1"
git push -u origin update-version-next-9.4.1
gh pr create --base 9.4 --head update-version-next-9.4.1 \
  --title "[Release] Update version to 9.4.1"

# PR 2: docs only
git checkout -b update-docs-version-9.4.1 origin/9.4
mage release:updatePatchDocs 9.4.1
git add -A && git commit -m "update docs version 9.4.1"
git push -u origin update-docs-version-9.4.1
gh pr create --base 9.4 --head update-docs-version-9.4.1 \
  --title "docs: update docs versions 9.4.1"
```

## Individual Commands

```bash
# Update version only
mage release:updateVersion 9.5.0

# Update docs only
mage release:updateDocs 9.5.0

# Update patch docs only (version.asciidoc)
mage release:updatePatchDocs 9.4.1

# Update mergify only
mage release:updateMergify 9.5.0

# See all release commands
mage -l | grep release
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CURRENT_RELEASE` | ✓ | - | Version to release (e.g., `9.5.0`) |
| `GITHUB_TOKEN` | ✓ | - | GitHub personal access token |
| `DRY_RUN` | | `false` | Preview mode (set to `true` to skip push/PR) |
| `BASE_BRANCH` | | `main` | Base branch for PRs |
| `PROJECT_OWNER` | | `elastic` | GitHub repository owner |
| `PROJECT_REPO` | | `elastic-agent` | Repository name |

## Troubleshooting

**"CURRENT_RELEASE environment variable not set"**
```bash
export CURRENT_RELEASE="9.5.0"
```

**"GITHUB_TOKEN environment variable not set"**
```bash
# Create token at: https://github.com/settings/tokens
export GITHUB_TOKEN="ghp_..."
```

**"failed to create branch: reference already exists"**
```bash
# Delete existing branch
git branch -D 9.5
# Or checkout existing branch
git checkout 9.5
```

## Full Documentation

For detailed documentation, see [dev-tools/mage/release/README.md](dev-tools/mage/release/README.md)

## Help

- **Issues**: https://github.com/elastic/elastic-agent/issues
- **Slack**: #ingest-team
- **Migration Plan**: [specs/MIGRATION_PLAN_ELASTIC_AGENT.md](specs/MIGRATION_PLAN_ELASTIC_AGENT.md)
