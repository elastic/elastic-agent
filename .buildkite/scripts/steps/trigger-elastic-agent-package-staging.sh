#!/usr/bin/env bash
#
# Create a dynamic buildkite step for testing the elastic-agent-package pipeline
# against the latest unified-release staging manifest.
#
# For PRs targeting a release branch (e.g. 9.5), the staging manifest for that
# branch is used directly. For PRs targeting main, the script falls back to the
# latest active release branch derived from .package-version.
#
# Required environment variables:
#  - BUILDKITE_PULL_REQUEST
#  - BUILDKITE_COMMIT
#  - BUILDKITE_BRANCH
#  - BUILDKITE_PULL_REQUEST_BASE_BRANCH
#

set -euo pipefail

STAGING_LATEST_BASE_URL="https://staging.elastic.co/latest"
BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

# Try to fetch a staging manifest for a given branch name.
fetch_staging_json() {
  curl -sf --retry 5 --retry-delay 5 --retry-all-errors \
    "${STAGING_LATEST_BASE_URL}/${1}.json" 2>/dev/null || true
}

STAGING_JSON=$(fetch_staging_json "${BASE_BRANCH}")

if [[ -z "${STAGING_JSON}" ]]; then
  # Base branch (e.g. "main") has no staging manifest — derive the latest
  # release branch from .package-version and try that, then one minor back
  # in case the current minor hasn't been released yet.
  CORE_VERSION=$(jq -r .core_version .package-version | sed 's/-SNAPSHOT//')
  MAJOR=$(echo "${CORE_VERSION}" | cut -d. -f1)
  MINOR=$(echo "${CORE_VERSION}" | cut -d. -f2)

  for TRY_MINOR in "${MINOR}" "$((MINOR - 1))"; do
    STAGING_JSON=$(fetch_staging_json "${MAJOR}.${TRY_MINOR}")
    [[ -n "${STAGING_JSON}" ]] && break
  done
fi

if [[ -z "${STAGING_JSON}" ]]; then
  echo "No staging manifest found for branch '${BASE_BRANCH}'; skipping staging package test." >&2
  exit 0
fi

MANIFEST_URL=$(echo "${STAGING_JSON}" | jq -r '.manifest_url')
STAGING_VERSION=$(echo "${STAGING_JSON}" | jq -r '.version')

cat << EOF
  - label: ":pipeline: Run elastic-agent-package against unified-release staging manifest"
    trigger: "elastic-agent-package"
    build:
      message: "#${BUILDKITE_PULL_REQUEST} - Verify elastic-agent-package works with staging manifest"
      commit: "${BUILDKITE_COMMIT}"
      branch: "${BUILDKITE_BRANCH}"
      env:
        AGENT_PACKAGE_VERSION: "${STAGING_VERSION}"
        DRA_VERSION: "${STAGING_VERSION}"
        DRA_WORKFLOW: "staging"
        DRA_BRANCH: "${BASE_BRANCH}"
        DRA_DRY_RUN: "--dry-run"
        MANIFEST_URL: "${MANIFEST_URL}"
        ELASTIC_SLACK_NOTIFICATIONS_ENABLED: "false"
EOF
