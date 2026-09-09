#!/usr/bin/env bash
#
# Create a dynamic buildkite step for testing the elastic-agent-package pipeline
# against the latest unified-release staging manifest.
#
# For PRs targeting a release branch (e.g. 9.5), the staging manifest for that
# branch is used directly. For PRs targeting main, the latest active release
# branch with an available staging manifest is used instead.
#
# Required environment variables:
#  - BUILDKITE_PULL_REQUEST
#  - BUILDKITE_COMMIT
#  - BUILDKITE_BRANCH
#  - BUILDKITE_PULL_REQUEST_BASE_BRANCH
#

set -euo pipefail

STAGING_LATEST_BASE_URL="https://staging.elastic.co/latest"
ACTIVE_BRANCHES_URL="https://elastic-release-api.s3.us-west-2.amazonaws.com/public/active-branches.txt"
BASE_BRANCH="${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"

# Fetches the staging manifest JSON for a given branch name.
# Prints the JSON and returns 0 on HTTP 200.
# Returns 1 on HTTP 404 (no staging manifest for this branch).
# Exits 1 on any other error (network failure, unexpected HTTP status).
fetch_staging_json() {
  local branch="$1"
  local http_code tmpfile exit_code
  tmpfile=$(mktemp)

  http_code=$(curl --retry 5 --retry-delay 5 \
    -o "${tmpfile}" -w '%{http_code}' \
    "${STAGING_LATEST_BASE_URL}/${branch}.json") || {
    exit_code=$?
    rm -f "${tmpfile}"
    echo "Failed to fetch staging manifest for branch '${branch}' (curl exit ${exit_code})" >&2
    exit 1
  }

  case "${http_code}" in
    200)
      cat "${tmpfile}"
      rm -f "${tmpfile}"
      ;;
    404)
      rm -f "${tmpfile}"
      return 1
      ;;
    *)
      rm -f "${tmpfile}"
      echo "Unexpected HTTP status ${http_code} fetching staging manifest for branch '${branch}'" >&2
      exit 1
      ;;
  esac
}

STAGING_JSON=$(fetch_staging_json "${BASE_BRANCH}") || true

if [[ -z "${STAGING_JSON}" ]]; then
  # Base branch (e.g. "main") has no staging manifest — find the latest active
  # release branch that does.
  ACTIVE_BRANCHES_CONTENT=$(curl --retry 5 --retry-delay 5 --retry-all-errors -fsSL "${ACTIVE_BRANCHES_URL}") || {
    echo "Failed to fetch active branches list from ${ACTIVE_BRANCHES_URL}" >&2
    exit 1
  }
  readarray -t ACTIVE_BRANCHES <<< "${ACTIVE_BRANCHES_CONTENT}"

  for BRANCH in "${ACTIVE_BRANCHES[@]}"; do
    [[ "${BRANCH}" == "main" ]] && continue
    STAGING_JSON=$(fetch_staging_json "${BRANCH}") || continue
    [[ -n "${STAGING_JSON}" ]] && break
  done
fi

if [[ -z "${STAGING_JSON}" ]]; then
  echo "No staging manifest found for any active branch; skipping staging package test." >&2
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
