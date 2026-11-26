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
# Dep teams publish latest pointers under "master.json" for their default branch.
DEP_BRANCH="${BRANCH}"
[[ "${BRANCH}" == "main" ]] && DEP_BRANCH="master"
WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"
GCS_BUCKET="${GCS_BUCKET:?GCS_BUCKET is required}"
BK_ORG="elastic"
BK_PIPELINE="elastic-agent-package"
PACKAGES_YML="dev-tools/packaging/packages.yml"

case "${WORKFLOW}" in
  snapshot) ARTIFACT_HOST="https://artifacts-snapshot.elastic.co" ;;
  staging)  ARTIFACT_HOST="https://artifacts-staging.elastic.co" ;;
  *) echo "ERROR: unknown workflow '${WORKFLOW}'" >&2; exit 1 ;;
esac

# Derive dep list from packages.yml projectName fields (the authoritative source).
# beats is a submodule dep not listed as a projectName, so it is added explicitly.
mapfile -t DEPS < <(
  { grep -E '^\s+projectName:' "${PACKAGES_YML}" | awk '{print $2}' | sort -u; echo "beats"; } | sort -u
)

echo "--- :mag: Checking dependency versions for elastic-agent-package (branch=${BRANCH}, workflow=${WORKFLOW})"

# --- Step 1: Load last-triggered dep build IDs from poller state -------------

declare -A LAST_DEP_BUILD_IDS

# Read the poller state file from GCS — this records the dep build IDs used by
# the last triggered build. The agent-package DRA manifest only contains the
# elastic-agent-package project (not dep projects), so reading build IDs from
# there always returns null and causes every dep to compare as changed.
POLLER_STATE_GCS_PATH="${GCS_BUCKET}/elastic-agent-package/poller-state/${BRANCH}.json"
POLLER_STATE=$(gsutil cat "gs://${POLLER_STATE_GCS_PATH}" 2>/dev/null || true)

if [[ -n "${POLLER_STATE}" ]]; then
  echo "Last poller state loaded from gs://${POLLER_STATE_GCS_PATH}"
  for dep in "${DEPS[@]}"; do
    build_id=$(echo "${POLLER_STATE}" | jq -r --arg dep "${dep}" \
      '.dep_build_ids[$dep] // empty' 2>/dev/null || true)
    LAST_DEP_BUILD_IDS["${dep}"]="${build_id:-}"
  done
else
  echo "No poller state found at gs://${POLLER_STATE_GCS_PATH} — cold start, will trigger unconditionally."
fi

# --- Step 2: Check each dependency for newer versions -----------------------

HAS_NEWER=false
declare -A CURRENT_BUILD_IDS

for dep in "${DEPS[@]}"; do
  latest_url="${ARTIFACT_HOST}/${dep}/latest/${DEP_BRANCH}.json"
  latest_json=$(curl -sf --retry 3 --retry-delay 5 "${latest_url}" 2>/dev/null || true)

  if [[ -z "${latest_json}" ]]; then
    echo "ERROR: no latest pointer for ${dep} on branch ${DEP_BRANCH}" >&2
    exit 1
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

if [[ "${HAS_NEWER}" == "false" && -n "${POLLER_STATE}" ]]; then
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
  echo "Will retry on the next poll tick."
  exit 0
fi

# --- Step 4: Merge dependency manifests -------------------------------------

echo "--- :compression: Merging dependency manifests"

MERGED_MANIFEST_FILE=$(mktemp --suffix=.json)
trap 'rm -f "${MERGED_MANIFEST_FILE}"' EXIT

PACKAGES_YML="${PACKAGES_YML}" \
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

# Determine DRA_VERSION from the first dep's latest pointer.
# For snapshot builds the version field includes -SNAPSHOT (e.g. 9.6.0-SNAPSHOT);
# for staging it does not (e.g. 9.6.0-rc1). Pass it as-is so the pipeline does
# not need to append or strip the qualifier.
FIRST_DEP="${DEPS[0]}"
FIRST_DEP_LATEST=$(curl -sf --retry 3 "${ARTIFACT_HOST}/${FIRST_DEP}/latest/${DEP_BRANCH}.json")
STACK_VERSION=$(echo "${FIRST_DEP_LATEST}" | jq -r '.version')

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

# --- Step 7: Save poller state to GCS -----------------------------------------
# Record the dep build IDs used for this trigger so the next poll tick can
# accurately detect whether anything has changed, without reading the DRA
# manifest (which only contains elastic-agent-package, not the dep projects).

echo "--- :gcloud: Saving poller state to gs://${POLLER_STATE_GCS_PATH}"
# Build dep_build_ids object from CURRENT_BUILD_IDS associative array
DEP_IDS_JSON="{}"
for dep in "${DEPS[@]}"; do
  bid="${CURRENT_BUILD_IDS[${dep}]:-}"
  DEP_IDS_JSON=$(echo "${DEP_IDS_JSON}" | jq --arg k "${dep}" --arg v "${bid}" '. + {($k): $v}')
done
jq -n --argjson ids "${DEP_IDS_JSON}" '{dep_build_ids: $ids}' \
  | gcloud storage cp \
      --content-type=application/json \
      --cache-control="no-store, no-cache, max-age=0" \
      - \
      "gs://${POLLER_STATE_GCS_PATH}"
