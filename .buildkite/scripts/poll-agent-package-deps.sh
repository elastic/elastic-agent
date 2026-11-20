#!/usr/bin/env bash
# Scheduled poller for elastic-agent-package DRA dependency changes.
#
# The decisions this script does NOT make live in Go, in `mage
# dra:mergeManifests` (see dev-tools/mage/dra): which products
# elastic-agent-package depends on, which DRA build of each is current, and what
# the merged manifest handed to packaging looks like. That is packaging logic
# and has to be runnable locally. What is left here is the CI plumbing — GCS and
# the Buildkite API — which cannot be run locally anyway.
#
# The contract between the two halves is the merged manifest's `build_id`: a
# content hash of the dependency build IDs. This script publishes the manifest
# under that id and records next to it that a build was triggered, so an input
# set that was already built is recognised on the next tick.
#
# Required env vars:
#   BUILDKITE_BRANCH     - release branch (e.g. "main", "9.6")
#   BUILDKITE_API_TOKEN  - Buildkite API token (read_builds, write_builds)
#   DRA_WORKFLOW         - "snapshot" or "staging"
#   GCS_BUCKET           - elastic-artifacts-snapshot or elastic-artifacts-staging
#
# Optional:
#   DRA_POLL_FORCE=true  - trigger even if this input set was already built
#   DRA_POLL_DRY_RUN=true - resolve and merge, but publish and trigger nothing
set -euo pipefail

_SELF=$(dirname "$0")
source "${_SELF}/common.sh"

BRANCH="${BUILDKITE_BRANCH:?BUILDKITE_BRANCH is required}"
WORKFLOW="${DRA_WORKFLOW:?DRA_WORKFLOW is required}"
GCS_BUCKET="${GCS_BUCKET:?GCS_BUCKET is required}"
DRY_RUN="${DRA_POLL_DRY_RUN:-false}"
FORCE="${DRA_POLL_FORCE:-false}"

BK_ORG="elastic"
BK_PIPELINE="elastic-agent-package"
MERGED_MANIFEST_FILE="${WORKSPACE}/build/dra/agent-artifacts-merged.json"
GCS_PREFIX="elastic-agent-package/poller-merged"

# The merged manifest has to be served from a host the packaging code is allowed
# to download manifests from; see AllowedManifestHosts in
# dev-tools/mage/manifest/manifest.go.
case "${GCS_BUCKET}" in
  elastic-artifacts-snapshot) ARTIFACT_HOST="artifacts-snapshot.elastic.co" ;;
  elastic-artifacts-staging)  ARTIFACT_HOST="artifacts-staging.elastic.co" ;;
  *) echo "ERROR: no public host known for bucket '${GCS_BUCKET}'" >&2; exit 1 ;;
esac

# --- Step 1: resolve dependencies and build the merged manifest --------------

echo "--- :mag: Resolving elastic-agent-package dependencies (branch=${BRANCH}, workflow=${WORKFLOW})"
mage dra:mergeManifests

DEPENDENCY_SET_ID=$(jq -r '.build_id' "${MERGED_MANIFEST_FILE}")
if [[ -z "${DEPENDENCY_SET_ID}" || "${DEPENDENCY_SET_ID}" == "null" ]]; then
  echo "ERROR: merged manifest ${MERGED_MANIFEST_FILE} has no build_id" >&2
  exit 1
fi
# The merged manifest's version is what the dependencies themselves report:
# "9.7.0-SNAPSHOT" for snapshots, "9.6.0-rc1" for staging. The pipeline passes
# it to dra-prep as stack_version verbatim, so pass it on unmodified.
STACK_VERSION=$(jq -r '.version' "${MERGED_MANIFEST_FILE}")
if [[ -z "${STACK_VERSION}" || "${STACK_VERSION}" == "null" ]]; then
  echo "ERROR: merged manifest ${MERGED_MANIFEST_FILE} has no version" >&2
  exit 1
fi

GCS_DIR="gs://${GCS_BUCKET}/${GCS_PREFIX}/${BRANCH}/${DEPENDENCY_SET_ID}"
MERGED_MANIFEST_URL="https://${ARTIFACT_HOST}/${GCS_PREFIX}/${BRANCH}/${DEPENDENCY_SET_ID}/agent-artifacts-merged.json"

# --- Step 2: has this exact set of dependency builds already been built? -----

if [[ "${FORCE}" != "true" ]]; then
  if gcloud storage ls "${GCS_DIR}/triggered.json" >/dev/null 2>&1; then
    echo "Dependency set ${DEPENDENCY_SET_ID} was already built — nothing to do."
    exit 0
  fi
fi

# A dry run stops here: everything below needs a Buildkite token.
if [[ "${DRY_RUN}" == "true" ]]; then
  echo "--- :no_entry: Dry run: would publish ${MERGED_MANIFEST_URL} and trigger ${BK_PIPELINE} on ${BRANCH}"
  exit 0
fi

# --- Step 3: stand down while a build is in flight ---------------------------

: "${BUILDKITE_API_TOKEN:?BUILDKITE_API_TOKEN is required unless DRA_POLL_DRY_RUN=true}"

echo "--- :buildkite: Checking for in-flight ${BK_PIPELINE} builds on ${BRANCH}"
RUNNING=$(curl -sf --retry 3 --retry-delay 5 \
  -H "Authorization: Bearer ${BUILDKITE_API_TOKEN}" \
  "https://api.buildkite.com/v2/organizations/${BK_ORG}/pipelines/${BK_PIPELINE}/builds?branch=${BRANCH}&state[]=creating&state[]=scheduled&state[]=running&per_page=1" \
  | jq 'length')

if [[ "${RUNNING}" -gt 0 ]]; then
  echo "A ${BK_PIPELINE} build is already running on ${BRANCH} — standing down."
  echo "The next poll picks up whatever is current then."
  exit 0
fi

# --- Step 4: publish the merged manifest -------------------------------------

echo "--- :gcloud: Publishing merged manifest to ${GCS_DIR}/agent-artifacts-merged.json"
gcloud storage cp \
  --content-type=application/json \
  --cache-control="no-store, no-cache, max-age=0" \
  "${MERGED_MANIFEST_FILE}" \
  "${GCS_DIR}/agent-artifacts-merged.json"

# --- Step 5: trigger the build -----------------------------------------------

echo "--- :pipeline: Triggering ${BK_PIPELINE}"
echo "  Branch:       ${BRANCH}"
echo "  DRA_VERSION:  ${STACK_VERSION}"
echo "  DRA_WORKFLOW: ${WORKFLOW}"
echo "  MANIFEST_URL: ${MERGED_MANIFEST_URL}"

BUILD_RESPONSE=$(curl -sf \
  -H "Authorization: Bearer ${BUILDKITE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  "https://api.buildkite.com/v2/organizations/${BK_ORG}/pipelines/${BK_PIPELINE}/builds" \
  -d "$(jq -n \
    --arg branch "${BRANCH}" \
    --arg version "${STACK_VERSION}" \
    --arg workflow "${WORKFLOW}" \
    --arg manifest_url "${MERGED_MANIFEST_URL}" \
    --arg set_id "${DEPENDENCY_SET_ID}" \
    '{
      commit: "HEAD",
      branch: $branch,
      message: ("DRA dependency poller: " + $workflow + " / " + $set_id),
      env: {
        DRA_WORKFLOW: $workflow,
        DRA_VERSION: $version,
        MANIFEST_URL: $manifest_url
      },
      ignore_pipeline_branch_filters: true
    }')")

BUILD_URL=$(echo "${BUILD_RESPONSE}" | jq -r '.web_url')
echo "Triggered ${BUILD_URL}"

# --- Step 6: record that this input set was built ----------------------------
#
# Written last, and only after the trigger succeeded: until it exists the
# dependency set counts as un-built, so a failed trigger is retried next tick.

echo "${BUILD_RESPONSE}" | jq \
  --arg set_id "${DEPENDENCY_SET_ID}" \
  --arg manifest_url "${MERGED_MANIFEST_URL}" \
  '{
    dependency_set_id: $set_id,
    merged_manifest_url: $manifest_url,
    build_number: .number,
    build_url: .web_url,
    triggered_at: (now | todate)
  }' > build/dra/triggered.json

gcloud storage cp \
  --content-type=application/json \
  --cache-control="no-store, no-cache, max-age=0" \
  "${WORKSPACE}/build/dra/triggered.json" \
  "${GCS_DIR}/triggered.json"
