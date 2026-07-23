#!/usr/bin/env bash
#
# Create a dynamic buildkite step for testing the elastic-agent-package pipeline
# against an independent agent release (IAR) staging manifest.
#
# Required environment variables:
#  - BUILDKITE_PULL_REQUEST
#  - BUILDKITE_COMMIT
#  - BUILDKITE_BRANCH
#  - BUILDKITE_PULL_REQUEST_BASE_BRANCH
#

set -euo pipefail

IAR_LATEST_BASE_URL="https://staging.elastic.co/independent-agent/latest"
BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

IAR_JSON=$(curl --silent --fail "${IAR_LATEST_BASE_URL}/${BASE_BRANCH}.json" 2>/dev/null || true)

if [[ -z "${IAR_JSON}" ]]; then
  echo "No IAR staging manifest for branch '${BASE_BRANCH}'; skipping IAR package test." >&2
  exit 0
fi

MANIFEST_URL=$(echo "${IAR_JSON}" | jq -r '.manifest_url')
IAR_VERSION=$(echo "${IAR_JSON}" | jq -r '.version')

cat << EOF
  - label: ":pipeline: Run elastic-agent-package against IAR staging manifest"
    trigger: "elastic-agent-package"
    build:
      message: "#${BUILDKITE_PULL_REQUEST} - Verify elastic-agent-package works with IAR staging manifest"
      commit: "${BUILDKITE_COMMIT}"
      branch: "${BUILDKITE_BRANCH}"
      env:
        AGENT_PACKAGE_VERSION: "${IAR_VERSION}"
        DRA_VERSION: "${IAR_VERSION}"
        DRA_WORKFLOW: "staging"
        DRA_BRANCH: "${BASE_BRANCH}"
        DRA_DRY_RUN: "--dry-run"
        MANIFEST_URL: "${MANIFEST_URL}"
        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"
EOF
