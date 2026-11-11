#!/usr/bin/env bash
# Poller for elastic-agent-package DRA dependency changes.
#
# Runs on a schedule. Checks whether any dependent product (beats, apm-server,
# fleet-server, cloud-defend, cloudbeat, elastic-agent-core) has a newer DRA
# build than what elastic-agent-package last built with. If so, merges the
# dependency manifests, uploads the merged manifest, and triggers a new
# elastic-agent-package build.
#
# Required env vars:
#   BUILDKITE_BRANCH      - release branch (e.g. "main", "9.6")
#   BUILDKITE_API_TOKEN   - Buildkite API token (read from Vault in the pipeline)
#   GCS_BUCKET            - GCS bucket for merged manifest upload
#                           (elastic-artifacts-snapshot or elastic-artifacts-staging)
#   DRA_WORKFLOW          - "snapshot" or "staging"
set -euo pipefail

BRANCH="${BUILDKITE_BRANCH:?BUILDKITE_BRANCH is required}"
WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"
GCS_BUCKET="${GCS_BUCKET:?GCS_BUCKET is required}"
BK_ORG="elastic"
BK_PIPELINE="elastic-agent-package"
DEPS_CONFIG=".buildkite/elastic-agent-package-deps.yaml"

case "${WORKFLOW}" in
  snapshot) ARTIFACT_HOST="https://artifacts-snapshot.elastic.co" ;;
  staging)  ARTIFACT_HOST="https://artifacts-staging.elastic.co" ;;
  *) echo "ERROR: unknown workflow '${WORKFLOW}'" >&2; exit 1 ;;
esac

# Read dependency list
mapfile -t DEPS < <(grep '^ *- ' "${DEPS_CONFIG}" | sed 's/^ *- //')

echo "--- :mag: Checking dependency versions for elastic-agent-package (branch=${BRANCH}, workflow=${WORKFLOW})"

# --- Step 1: Get the version elastic-agent-package last built with -----------

AGENT_PKG_LATEST_URL="${ARTIFACT_HOST}/elastic-agent-package/latest/${BRANCH}.json"
AGENT_PKG_LATEST=$(curl -sf --retry 3 --retry-delay 5 "${AGENT_PKG_LATEST_URL}" 2>/dev/null || true)

declare -A LAST_DEP_BUILD_IDS

if [[ -n "${AGENT_PKG_LATEST}" ]]; then
  AGENT_PKG_MANIFEST_URL=$(echo "${AGENT_PKG_LATEST}" | jq -r '.manifest_url')
  echo "Last elastic-agent-package manifest: ${AGENT_PKG_MANIFEST_URL}"

  # Read dependency build IDs embedded in the last agent-package manifest
  AGENT_PKG_MANIFEST=$(curl -sf --retry 3 --retry-delay 5 "${AGENT_PKG_MANIFEST_URL}" 2>/dev/null || true)
  if [[ -n "${AGENT_PKG_MANIFEST}" ]]; then
    for dep in "${DEPS[@]}"; do
      build_id=$(echo "${AGENT_PKG_MANIFEST}" | jq -r --arg dep "${dep}" \
        '.projects[$dep].build_id // empty' 2>/dev/null || true)
      LAST_DEP_BUILD_IDS["${dep}"]="${build_id:-}"
    done
  fi
else
  echo "No existing elastic-agent-package latest pointer found on branch ${BRANCH} — cold start, will trigger unconditionally."
fi

# --- Step 2: Check each dependency for newer versions -----------------------

HAS_NEWER=false
declare -A CURRENT_BUILD_IDS

for dep in "${DEPS[@]}"; do
  latest_url="${ARTIFACT_HOST}/${dep}/latest/${BRANCH}.json"
  latest_json=$(curl -sf --retry 3 --retry-delay 5 "${latest_url}" 2>/dev/null || true)

  if [[ -z "${latest_json}" ]]; then
    echo "WARNING: no latest pointer for ${dep} on branch ${BRANCH}, skipping"
    continue
  fi

  current_build_id=$(echo "${latest_json}" | jq -r '.build_id')
  CURRENT_BUILD_IDS["${dep}"]="${current_build_id}"
  last_build_id="${LAST_DEP_BUILD_IDS[${dep}]:-}"

  if [[ "${current_build_id}" != "${last_build_id}" ]]; then
    echo "  ${dep}: NEWER (was '${last_build_id}', now '${current_build_id}')"
    HAS_NEWER=true
  else
    echo "  ${dep}: up to date (${current_build_id})"
  fi
done

if [[ "${HAS_NEWER}" == "false" && -n "${AGENT_PKG_LATEST}" ]]; then
  echo "All dependencies are up to date — nothing to do."
  exit 0
fi

# --- Step 3: Check if a build is already running ----------------------------

echo "--- :buildkite: Checking for in-flight elastic-agent-package builds on branch ${BRANCH}"

RUNNING=$(curl -sf --retry 3 \
  -H "Authorization: Bearer ${BUILDKITE_API_TOKEN}" \
  "https://api.buildkite.com/v2/organizations/${BK_ORG}/pipelines/${BK_PIPELINE}/builds?branch=${BRANCH}&state[]=running&state[]=scheduled&per_page=1" \
  | jq 'length')

if [[ "${RUNNING}" -gt 0 ]]; then
  echo "An elastic-agent-package build is already running on branch ${BRANCH} — skipping trigger."
  echo "The in-flight build will pick up the latest dependency versions."
  exit 0
fi

# --- Step 4: Merge dependency manifests -------------------------------------

echo "--- :compression: Merging dependency manifests"

MERGED_MANIFEST_FILE=$(mktemp --suffix=.json)
trap 'rm -f "${MERGED_MANIFEST_FILE}"' EXIT

DEPS_CONFIG="${DEPS_CONFIG}" \
  .buildkite/scripts/merge-dep-manifests.sh "${WORKFLOW}" "${BRANCH}" "${MERGED_MANIFEST_FILE}"

# --- Step 5: Upload merged manifest to GCS ----------------------------------

TIMESTAMP=$(date -u +%Y%m%d%H%M%S)
MERGED_MANIFEST_GCS_PATH="${GCS_BUCKET}/elastic-agent-package/poller-merged/${BRANCH}/${TIMESTAMP}/agent-artifacts-merged.json"
# GCS buckets are fronted by elastic.co CDN domains that are in the packaging allowlist.
# elastic-artifacts-snapshot → artifacts-snapshot.elastic.co
# elastic-artifacts-staging  → artifacts-staging.elastic.co
ARTIFACT_HOST_DOMAIN="${GCS_BUCKET/elastic-artifacts-/artifacts-}.elastic.co"
MERGED_MANIFEST_URL="https://${ARTIFACT_HOST_DOMAIN}/elastic-agent-package/poller-merged/${BRANCH}/${TIMESTAMP}/agent-artifacts-merged.json"

echo "--- :gcloud: Uploading merged manifest to gs://${MERGED_MANIFEST_GCS_PATH}"
gcloud storage cp \
  --content-type=application/json \
  --cache-control="no-store, no-cache, max-age=0" \
  "${MERGED_MANIFEST_FILE}" \
  "gs://${MERGED_MANIFEST_GCS_PATH}"

# --- Step 6: Trigger elastic-agent-package build ----------------------------

# Translate main → main (no change needed; elastic-agent-package uses main directly)
AGENT_PKG_BRANCH="${BRANCH}"

# Determine DRA_VERSION from branch: strip -SNAPSHOT suffix if present, derive semver
# The latest pointer's version field gives us the base version
FIRST_DEP="${DEPS[0]}"
FIRST_DEP_LATEST=$(curl -sf --retry 3 "${ARTIFACT_HOST}/${FIRST_DEP}/latest/${BRANCH}.json")
STACK_VERSION=$(echo "${FIRST_DEP_LATEST}" | jq -r '.version' | sed 's/-SNAPSHOT//')

echo "--- :pipeline: Triggering elastic-agent-package build"
echo "  Branch:       ${AGENT_PKG_BRANCH}"
echo "  DRA_VERSION:  ${STACK_VERSION}"
echo "  DRA_WORKFLOW: ${WORKFLOW}"
echo "  MANIFEST_URL: ${MERGED_MANIFEST_URL}"

curl -sf \
  -H "Authorization: Bearer ${BUILDKITE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://api.buildkite.com/v2/organizations/${BK_ORG}/pipelines/${BK_PIPELINE}/builds" \
  -d "$(jq -n \
    --arg branch "${AGENT_PKG_BRANCH}" \
    --arg version "${STACK_VERSION}" \
    --arg workflow "${WORKFLOW}" \
    --arg manifest_url "${MERGED_MANIFEST_URL}" \
    '{
      branch: $branch,
      message: ("Poller-triggered build: " + $workflow + " / " + $version),
      env: {
        DRA_WORKFLOW: $workflow,
        DRA_VERSION: $version,
        MANIFEST_URL: $manifest_url
      },
      ignore_pipeline_branch_filters: true
    }')"

echo "Triggered elastic-agent-package build on branch ${AGENT_PKG_BRANCH}."
