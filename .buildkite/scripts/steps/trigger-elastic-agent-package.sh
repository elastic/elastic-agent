#!/usr/bin/env bash
#
# Create a dynamic buildkite step for running the elastic-agent-package pipeline.
#
# Required environment variables:
#  - BUILDKITE_PULL_REQUEST
#  - BUILDKITE_COMMIT
#  - BUILDKITE_BRANCH
#

if [ ! -f .package-version ]; then
  echo ".package-version file not found!"
  exit 1
fi

BEAT_VERSION=$(jq -r .version .package-version)
MANIFEST_URL=$(jq -r .manifest_url .package-version)

cat << EOF
  - label: ":pipeline: Run elastic-agent-package"
    trigger: "elastic-agent-package"
    build:
      message: "${BUILDKITE_PULL_REQUEST} - Test packaging works as expected"
      commit: "${BUILDKITE_COMMIT}"
      branch: "${BUILDKITE_BRANCH}"
    env:
      DRA_VERSION: "${BEAT_VERSION}"
      DRA_WORKFLOW: "snapshot"
      DRA_DRY_RUN: "--dry-run"
      MANIFEST_URL: "${MANIFEST_URL}"
      ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"
EOF
