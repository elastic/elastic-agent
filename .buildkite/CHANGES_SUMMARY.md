# Kubernetes Testing Tier Implementation - Summary

## Changes Made

This implementation introduces a tier-based Kubernetes testing strategy to optimize CI resources while maintaining test coverage.

### Files Created

1. **`.buildkite/k8s-testing-pipeline.yml`**
   - New dynamic K8s test pipeline template
   - Matrix configuration is injected at runtime based on tier

2. **`.buildkite/scripts/upload-k8s-tests.sh`**
   - Script that determines which test tier to run
   - Checks for packaging file modifications in PRs
   - Generates appropriate test matrix and uploads pipeline

3. **`.github/workflows/k8s-tier3-scheduled.yml`**
   - GitHub Actions workflow for scheduled Tier 3 tests
   - Runs daily at 2:00 AM UTC
   - Triggers Buildkite with `K8S_SCHEDULED_TIER3=true`

4. **`.buildkite/K8S_TESTING.md`**
   - Comprehensive documentation of the tier system
   - Explains tier definitions, triggers, and implementation

5. **`.buildkite/CHANGES_SUMMARY.md`**
   - This file - summary of changes

### Files Modified

1. **`.buildkite/bk.integration.pipeline.yml`**
   - Replaced inline K8s test definitions with single upload step
   - Calls `upload-k8s-tests.sh` to dynamically generate tests

## Test Tier Behavior

### Current Behavior

| Build Type | Tier | K8s Versions | Container Images | Job Count |
|------------|------|--------------|------------------|-----------|
| PR (default) | Tier 1 | Min + Max (2) | Basic only (1) | **2** |
| PR (packaging files) | Tier 2 | Min + Max (2) | All (9) | **18** |
| Branch commit | Tier 2 | Min + Max (2) | All (9) | **18** |
| Scheduled | Tier 3 | All (8) | All (9) | **72** |

### Previous Behavior

| Build Type | K8s Versions | Container Images | Job Count |
|------------|--------------|------------------|-----------|
| PR | Min + Max (2) | All (9) | **18** |
| Branch commit | All (8) | 2 groups | **16** |

### Resource Savings

- **PR builds**: ~89% reduction (18 → 2 jobs) for non-packaging changes
- **Branch builds**: Slightly more jobs (16 → 18) but better coverage
- **Scheduled builds**: Comprehensive coverage (72 jobs) without blocking PRs

## Packaging Files Trigger

PRs trigger Tier 2 testing when modifying:
- `.buildkite/**`
- `magefile.go`
- `dev-tools/**`
- `go.mod`
- `go.sum`

## Testing the Changes

### Local Testing

Test which tier would be selected:

```bash
# PR without packaging changes
BUILDKITE_PULL_REQUEST="123" \
BUILDKITE_PULL_REQUEST_BASE_BRANCH="main" \
.buildkite/scripts/upload-k8s-tests.sh

# Branch build
BUILDKITE_PULL_REQUEST="false" \
.buildkite/scripts/upload-k8s-tests.sh

# Scheduled Tier 3
K8S_SCHEDULED_TIER3="true" \
.buildkite/scripts/upload-k8s-tests.sh
```

### Validation Checklist

Before merging:

- [ ] Shell script passes syntax check: `bash -n .buildkite/scripts/upload-k8s-tests.sh`
- [ ] YAML files are valid (validated by Buildkite on upload)
- [ ] Tier logic tested locally (see above)
- [ ] Script is executable: `chmod +x .buildkite/scripts/upload-k8s-tests.sh`
- [ ] Documentation is complete

## Next Steps

1. **Merge this PR** to enable the new tier system
2. **Monitor first scheduled run** to ensure Tier 3 works correctly
3. **Watch PR builds** to verify Tier 1/Tier 2 selection works
4. **Update K8s versions** in upload-k8s-tests.sh when support matrix changes

## Rollback Plan

If issues arise:

1. Revert changes to `.buildkite/bk.integration.pipeline.yml`
2. Restore original K8s test definitions from git history
3. Disable scheduled workflow in GitHub Actions

## Notes

- The scheduled workflow requires a `BUILDKITE_TOKEN` secret in GitHub
- K8s version list must stay in sync between upload script and main pipeline
- Packaging file patterns can be adjusted in `upload-k8s-tests.sh`
