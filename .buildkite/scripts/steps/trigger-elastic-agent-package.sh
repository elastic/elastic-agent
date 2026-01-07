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

BEAT_VERSION="$(jq -r .core_version .package-version)"

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
        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"
EOF
