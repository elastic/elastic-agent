#!/bin/bash

set -eo pipefail

# Prints stack version for current or target release branch without '-SNAPSHOT' suffix 
# example: 
# BUILDKITE_PULL_REQUEST_BASE_BRANCH=8.x .buildkite/scripts/test.sh
# 8.19.0-64846b77
getStableEssSnapshotForBranch() {
  set -eo pipefail

  # If we're on a pull request, use the base branch. Otherwise, use the current branch.
  # This is Buildkite specific
  baseStackBranch="${BUILDKITE_PULL_REQUEST_BASE_BRANCH:-${BUILDKITE_BRANCH}}"

  # If no base branch is found, fallback to .package-version content.
  if [ -z "$baseStackBranch" ]; then
    cat .package-version
    return
  fi

  # Fetch the branch channel URL for the base branch if it exists, and the content contains .build.
  branchChannelURL="https://storage.googleapis.com/artifacts-api/channels/${baseStackBranch}.json"
  if ! curl --silent --fail "$branchChannelURL" | jq -r .build; then
    cat .package-version
  fi
}
STABLE_ESS_VERSION=$(getStableEssSnapshotForBranch)
echo "Stable ESS Version: $STABLE_ESS_VERSION"
buildkite-agent meta-data set "stable.ess.version" $STABLE_ESS_VERSION