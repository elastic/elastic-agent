#!/usr/bin/env bash
#
# Create a dynamic buildkite step for running the elastic-agent-package pipeline.
#
# Required environment variables:
#  - BUILDKITE_PULL_REQUEST
#  - BUILDKITE_COMMIT
#  - BUILDKITE_BRANCH
#  - BUILDKITE_PULL_REQUEST_BASE_BRANCH
#

if [ ! -f .package-version ]; then
  echo ".package-version file not found!"
  exit 1
fi

# No need for the snapshot but the three digits version is required
BEAT_VERSION=$(jq -r .version .core_version)
MANIFEST_URL=$(jq -r .manifest_url .package-version)

cat << EOF
  - label: ":pipeline: Run elastic-agent-package"
    trigger: "elastic-agent-package"
    build:
      message: "#${BUILDKITE_PULL_REQUEST} - Verify elastic-agent-package works"
      commit: "${BUILDKITE_COMMIT}"
      branch: "${BUILDKITE_BRANCH}"
      env:
        DRA_VERSION: "${BEAT_VERSION}"
        DRA_WORKFLOW: "snapshot"
        DRA_BRANCH: "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
        DRA_DRY_RUN: "--dry-run"
        MANIFEST_URL: "${MANIFEST_URL}"
        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"
EOF
