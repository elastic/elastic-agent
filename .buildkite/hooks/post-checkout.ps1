# Set error handling
$ErrorActionPreference = "Stop"

# Fix CRLF before any git operations to prevent line ending conflicts
git config core.autocrlf true

# Define a function to checkout and merge
# This merges the target branch INTO the current PR branch instead of the other way around.
# This avoids the Windows file locking issue where git cannot replace the currently
# running script when checking out a different branch.
function Checkout-Merge {
    param (
        [string]$targetBranch,
        [string]$prCommit,
        [string]$mergeBranch
    )

    if (-not $targetBranch) {
        Write-Host "No pull request target branch"
        exit 1
    }

    # Create a merge branch from the current PR commit
    git checkout -b $mergeBranch
    Write-Host "New branch created: $(git rev-parse --abbrev-ref HEAD)"

    # Set author identity so it can be used for git merge
    git config user.name "github-merged-pr-post-checkout"
    git config user.email "auto-merge@buildkite"

    # Fetch and merge the target branch into the PR branch
    # This is equivalent to merging PR into target, but avoids having to checkout
    # the target branch (which would fail due to Windows file locking on this script)
    git fetch -v origin $targetBranch
    git merge --no-edit FETCH_HEAD

    if ($LASTEXITCODE -ne 0) {
        $mergeResult = $LASTEXITCODE
        Write-Host "Merge failed: $mergeResult"
        git merge --abort
        exit $mergeResult
    }
}

$pullRequest = $env:BUILDKITE_PULL_REQUEST

if ($pullRequest -ne "false") {
    $targetBranch = $env:BUILDKITE_PULL_REQUEST_BASE_BRANCH
    $prCommit = $env:BUILDKITE_COMMIT
    $prId = $env:BUILDKITE_PULL_REQUEST
    $mergeBranch = "pr_merge_$prId"

    Checkout-Merge $targetBranch $prCommit $mergeBranch

    Write-Host "Commit information"
    git --no-pager log --format=%B -n 1
}

# Initialize submodules if they exist
if (Test-Path ".gitmodules") {
    Write-Host "Initializing submodules"
    git submodule update --init --progress
}

# Ensure Buildkite groups are rendered
Write-Host ""
