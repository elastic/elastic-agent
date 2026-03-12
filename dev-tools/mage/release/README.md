# Elastic Agent Release Automation

This directory contains the mage-based release automation system for elastic-agent. It replaces the previous Makefile-based scripts with pure Go implementations.

## Quick Start

### Automated Workflow (Recommended)

```bash
# Set required environment variables
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"

# Run the complete major/minor release workflow
mage release:runMajorMinor

# Or for patch releases (from release branch)
export CURRENT_RELEASE="9.4.1"
export BASE_BRANCH="9.4"
mage release:runPatch
```

### Manual Step-by-Step

```bash
# 1. Prepare release files
mage release:prepareMajorMinor

# 2. Create release branch and commit
mage release:createBranch

# 3. Create pull request on GitHub
mage release:createPR
```

## Prerequisites

### Required Tools

- **Go 1.24+** - Check your version: `go version`
- **Git** - For repository operations
- **Mage** - Install with: `go install github.com/magefile/mage@latest`

### Required Access

- **GitHub Token** - Personal access token with `repo` scope
  - Create at: https://github.com/settings/tokens
  - Required permissions: `repo` (full control of private repositories)
  - Set as environment variable: `export GITHUB_TOKEN="ghp_..."`

- **Git Configuration** - Ensure git is configured:
  ```bash
  git config --global user.name "Your Name"
  git config --global user.email "your.email@elastic.co"
  ```

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `CURRENT_RELEASE` | Version to release | `9.5.0` |
| `GITHUB_TOKEN` | GitHub personal access token | `ghp_abc123...` |

### Optional (with defaults)

| Variable | Description | Default |
|----------|-------------|---------|
| `DRY_RUN` | Preview mode (no push/PR) | `false` |
| `BASE_BRANCH` | Base branch for PRs | `main` |
| `PROJECT_OWNER` | GitHub repository owner | `elastic` |
| `PROJECT_REPO` | GitHub repository name | `elastic-agent` |
| `GIT_AUTHOR_NAME` | Commit author name | `elastic-machine` |
| `GIT_AUTHOR_EMAIL` | Commit author email | `infra-root+elasticmachine@elastic.co` |

## Available Commands

### File Updates

```bash
# Update version in version/version.go
mage release:updateVersion 9.5.0

# Update K8s manifests with new version
mage release:updateDocs 9.5.0

# Add backport rule to .mergify.yml
mage release:updateMergify 9.5.0
```

### Orchestration Commands (New!)

```bash
# Complete major/minor release workflow
mage release:runMajorMinor

# Complete patch release workflow
mage release:runPatch
```

### Individual Step Commands

```bash
# Prepare major/minor release (updates all files)
mage release:prepareMajorMinor

# Create release branch with changes committed
mage release:createBranch

# Create pull request on GitHub
mage release:createPR
```

## Dry Run Mode

**Always test with DRY_RUN first!**

The `DRY_RUN` environment variable allows you to preview the release workflow without making any destructive changes:

```bash
# Test the workflow without pushing or creating PRs
export DRY_RUN=true
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_..."

mage release:runMajorMinor
```

**What DRY_RUN does:**
- ✅ Updates local files (version, docs, mergify)
- ✅ Shows what commands would be executed
- ❌ Does NOT create branches on remote
- ❌ Does NOT push changes
- ❌ Does NOT create pull requests

**After dry run:**
```bash
# Review changes
git diff

# If satisfied, run for real
export DRY_RUN=false
mage release:runMajorMinor

# Or discard changes
git checkout .
```

## Release Workflows

### Major/Minor Release (e.g., 9.5.0)

#### Automated Workflow (Recommended)

**1. Dry run first (always!):**

```bash
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="ghp_your_token_here"
export DRY_RUN=true

# Test the workflow
mage release:runMajorMinor

# Review the changes
git diff
```

**2. Run for real:**

```bash
# Ensure you're on main
git checkout main
git pull origin main

# Disable dry run
export DRY_RUN=false

# Run the complete workflow
mage release:runMajorMinor
```

This will:
1. Check requirements (git status, etc.)
2. Update all release files (version, docs, mergify)
3. Create release branch (e.g., `9.5`)
4. Commit all changes
5. Push branch to remote
6. Create pull request on GitHub

**Done!** The PR is created and ready for review.

---

#### Manual Step-by-Step Workflow

**1. Prepare your environment:**

```bash
# Set the release version
export CURRENT_RELEASE="9.5.0"

# Set your GitHub token
export GITHUB_TOKEN="ghp_your_token_here"

# Optional: Set base branch if not 'main'
export BASE_BRANCH="main"
```

**2. Ensure you're on the correct branch:**

```bash
# Start from a clean main branch
git checkout main
git pull origin main

# Verify no uncommitted changes
git status
```

**3. Prepare release files:**

```bash
mage release:prepareMajorMinor
```

This command will:
- Update `version/version.go` to the new version
- Update K8s manifests in `deploy/kubernetes/`
- Add backport rule to `.mergify.yml`

**4. Review the changes:**

```bash
git diff
```

Verify:
- Version is correct in `version/version.go`
- K8s manifests have correct image tags
- Mergify config has new backport rule for `9.5`

**5. Create release branch:**

```bash
mage release:createBranch
```

This will:
- Create and checkout a new branch `9.5`
- Commit all changes with message: `[Release] Prepare release 9.5.0`
- Branch is ready to be pushed

**6. Push the branch:**

```bash
git push origin 9.5
```

**7. Create pull request:**

```bash
mage release:createPR
```

This creates a PR from `9.5` → `main` with:
- Title: `[Release 9.5.0] Prepare release branch`
- Auto-generated checklist
- Release notes template

### Patch Release (e.g., 9.4.1)

#### Automated Workflow (Recommended)

**1. Dry run first:**

```bash
export CURRENT_RELEASE="9.4.1"
export BASE_BRANCH="9.4"
export GITHUB_TOKEN="ghp_your_token_here"
export DRY_RUN=true

# Checkout the release branch
git checkout 9.4
git pull origin 9.4

# Test the workflow
mage release:runPatch

# Review changes
git diff
```

**2. Run for real:**

```bash
# Disable dry run
export DRY_RUN=false

# Run the complete workflow
mage release:runPatch
```

This will:
1. Check requirements
2. Verify you're on the release branch
3. Update version files
4. Commit changes
5. Push to remote

**Done!** Changes are pushed to the release branch.

---

#### Manual Workflow

For patch releases, the manual process targets the existing release branch:

```bash
# Set the patch version
export CURRENT_RELEASE="9.4.1"
export BASE_BRANCH="9.4"  # Target the release branch
export GITHUB_TOKEN="ghp_..."

# Checkout the release branch
git checkout 9.4
git pull origin 9.4

# Prepare files
mage release:updateVersion 9.4.1
mage release:updateDocs 9.4.1

# Commit and push
git add -A
git commit -m "[Release] Prepare patch release 9.4.1"
git push origin 9.4
```

## Local Development & Testing

### Test the Functions Locally

You can test individual functions without creating actual branches:

```bash
# Test version update
mage release:updateVersion 9.5.0-test

# Check the change
git diff version/version.go

# Revert
git checkout version/version.go
```

### Run Unit Tests

```bash
# Run all tests
go test ./dev-tools/mage/release/...

# Run with coverage
go test -cover ./dev-tools/mage/release/...

# Run specific test
go test -run TestUpdateVersion ./dev-tools/mage/release/...

# Verbose output
go test -v ./dev-tools/mage/release/...
```

### Test on a Fork

Before running on the main repository, test on a fork:

```bash
export PROJECT_OWNER="your-github-username"
export PROJECT_REPO="elastic-agent"
export CURRENT_RELEASE="9.5.0-test"
export GITHUB_TOKEN="ghp_..."

# Run through the workflow
mage release:prepareMajorMinor
mage release:createBranch
mage release:createPR
```

## Troubleshooting

### "CURRENT_RELEASE environment variable not set"

**Solution:** Set the version you want to release:
```bash
export CURRENT_RELEASE="9.5.0"
```

### "GITHUB_TOKEN environment variable not set"

**Solution:** Create and set a GitHub personal access token:
```bash
# Create token at: https://github.com/settings/tokens
export GITHUB_TOKEN="ghp_your_token_here"
```

### "failed to open git repo"

**Solution:** Ensure you're in the elastic-agent repository root:
```bash
cd /path/to/elastic-agent
pwd  # Should show elastic-agent directory
```

### "failed to create branch: reference already exists"

**Solution:** The branch already exists. Either:
- Delete the existing branch: `git branch -D 9.5`
- Checkout the existing branch: `git checkout 9.5`
- Use a different version number

### "failed to push: authentication required"

**Solution:** Configure git credentials or use SSH:
```bash
# Option 1: Use SSH
git remote set-url origin git@github.com:elastic/elastic-agent.git

# Option 2: Configure credentials
git config credential.helper store
```

### PR creation fails with "422 Validation Failed"

**Possible causes:**
- Branch doesn't exist on remote (push first: `git push origin 9.5`)
- PR already exists for this branch
- Invalid base branch specified

**Solution:**
```bash
# Ensure branch is pushed
git push origin 9.5

# Check existing PRs
gh pr list --head 9.5
```

## CI/CD Integration

### Buildkite

The release automation integrates with Buildkite pipelines:

```yaml
# .buildkite/pipeline-release-major-minor.yml
steps:
  - label: "Prepare Release"
    command: |
      export CURRENT_RELEASE="${RELEASE_VERSION}"
      export GITHUB_TOKEN="${GITHUB_TOKEN_SECRET}"
      mage release:prepareMajorMinor
      mage release:createBranch
      mage release:createPR
```

### Manual Trigger

You can manually trigger releases from CI by setting environment variables in the Buildkite UI.

## Migration from Makefile

If you're migrating from the old `elastic-agent.mak` system:

| Old Makefile Target | New Mage Command | Notes |
|---------------------|------------------|-------|
| `make update-version` | `mage release:updateVersion` | Same functionality |
| `make update-docs` | `mage release:updateDocs` | Updates K8s manifests |
| `make update-mergify` | `mage release:updateMergify` | Adds backport rules |
| `make prepare-major-minor-release` | `mage release:prepareMajorMinor` | Orchestrates all updates |
| `make create-branch-major-minor-release` | `mage release:createBranch` | Creates and commits to branch |
| N/A | `mage release:createPR` | New: Creates PR via GitHub API |

### Key Differences

- **No external tools needed**: No `hub`, `gh`, `sed`, `yq`, or Python
- **Pure Go**: All logic in Go, better testing and type safety
- **Integrated**: Part of existing magefile, consistent with project
- **Better error handling**: Type-safe APIs with proper error messages

## Architecture

### File Structure

```
dev-tools/mage/release/
├── release.go      # Main release functions
├── git.go          # Git operations (branch, commit, push)
├── github.go       # GitHub API integration (PR creation)
├── release_test.go # Tests for release functions
└── git_test.go     # Tests for git operations
```

### Dependencies

- `github.com/go-git/go-git/v5` - Git operations in pure Go
- `github.com/google/go-github/v68` - GitHub API client
- `gopkg.in/yaml.v3` - YAML parsing for mergify config

## Best Practices

### Before Running

1. **Always start from a clean state:**
   ```bash
   git checkout main
   git pull origin main
   git status  # Should be clean
   ```

2. **Set environment variables explicitly:**
   ```bash
   export CURRENT_RELEASE="9.5.0"
   export GITHUB_TOKEN="ghp_..."
   ```

3. **Review changes before pushing:**
   ```bash
   git diff
   git log --oneline -1
   ```

### During Release

1. **Test on a fork first** if you're unsure
2. **Verify versions** in all updated files
3. **Check CI status** before merging PRs
4. **Communicate with team** about release timing

### After Release

1. **Document any issues** encountered
2. **Update this README** if you found gaps
3. **Run tests** to ensure nothing broke

## Getting Help

- **Issues with this tool**: Create an issue in `elastic/elastic-agent`
- **Questions**: Ask in #ingest-team Slack channel
- **Documentation**: This README or `specs/MIGRATION_PLAN_ELASTIC_AGENT.md`

## Examples

### Complete Automated Workflow

```bash
#!/bin/bash
# Example: Release 9.5.0 with dry run first

set -e  # Exit on error

# Configuration
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="${GITHUB_TOKEN}"  # From your environment
export BASE_BRANCH="main"

echo "=== Preparing release ${CURRENT_RELEASE} ==="

# Ensure clean state
git checkout main
git pull origin main

# DRY RUN FIRST
echo "Step 1: Running dry run..."
export DRY_RUN=true
mage release:runMajorMinor

# Review changes
echo ""
echo "Step 2: Review changes..."
git diff

read -p "Do the changes look correct? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborting release. Run 'git checkout .' to discard changes."
    exit 1
fi

# RUN FOR REAL
echo ""
echo "Step 3: Running for real..."
export DRY_RUN=false
mage release:runMajorMinor

echo ""
echo "=== Release preparation complete! ==="
echo "PR created. Review and merge when ready."
```

### Complete Manual Workflow

```bash
#!/bin/bash
# Example: Release 9.5.0 (manual steps)

set -e  # Exit on error

# Configuration
export CURRENT_RELEASE="9.5.0"
export GITHUB_TOKEN="${GITHUB_TOKEN}"
export BASE_BRANCH="main"

echo "=== Preparing release ${CURRENT_RELEASE} ==="

# Ensure clean state
git checkout main
git pull origin main

# Prepare files
echo "Step 1: Preparing release files..."
mage release:prepareMajorMinor

# Review changes
echo "Step 2: Review changes..."
git diff

read -p "Do the changes look correct? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborting release. Run 'git checkout .' to discard changes."
    exit 1
fi

# Create branch
echo "Step 3: Creating release branch..."
mage release:createBranch

# Push branch
echo "Step 4: Pushing to remote..."
git push origin 9.5

# Create PR
echo "Step 5: Creating pull request..."
mage release:createPR

echo "=== Release preparation complete! ==="
echo "PR created. Review and merge when ready."
```

### Quick Update (Single File)

```bash
# Just update version
mage release:updateVersion 9.5.0

# Just update docs
mage release:updateDocs 9.5.0

# Just update mergify
mage release:updateMergify 9.5.0
```

## FAQ

**Q: Can I run this on my local machine?**
A: Yes! That's the primary use case. Just set the environment variables and run the commands.

**Q: Do I need Docker?**
A: No, everything runs in pure Go.

**Q: What if I make a mistake?**
A: Before pushing, you can reset with `git reset --hard origin/main`. After pushing, you can delete the branch and start over.

**Q: Can I use this for patch releases?**
A: Yes, set `BASE_BRANCH` to the release branch (e.g., `9.4`) and run the same commands.

**Q: How do I test without affecting production?**
A: Use a fork by setting `PROJECT_OWNER` to your GitHub username.

**Q: Where are the release scripts now?**
A: They're in `dev-tools/mage/release/` as Go code, integrated into the existing magefile.

## Version History

- **v1.0** (2026-03-12): Initial implementation with core functionality
  - File updates (version, docs, mergify)
  - Git operations (branch, commit, push)
  - GitHub PR creation
  - Unit tests with 60%+ coverage
