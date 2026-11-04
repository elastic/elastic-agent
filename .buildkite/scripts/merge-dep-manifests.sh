#!/usr/bin/env bash
# Fetches the latest DRA manifest for each dependent product and merges them
# into a single manifest JSON that elastic-agent-package's packaging code can
# consume via MANIFEST_URL (same format as the release-manager merged manifest).
#
# Usage:
#   merge-dep-manifests.sh <workflow> <branch> <output-file>
#
# Arguments:
#   workflow    - "snapshot" or "staging"
#   branch      - release branch (e.g. "main", "9.6")
#   output-file - path to write the merged manifest JSON
#
# The merged manifest is a JSON object with a top-level "projects" map,
# where each key is a product name and the value contains the product's
# external_artifacts_manifest_url (pointing to its own DRA manifest).
# This is the format elastic-agent's packaging code (manifest.go) expects.
set -euo pipefail

WORKFLOW="${1:?workflow argument required (snapshot|staging)}"
BRANCH="${2:?branch argument required}"
OUTPUT_FILE="${3:?output-file argument required}"

DEPS_CONFIG="${DEPS_CONFIG:-.buildkite/elastic-agent-package-deps.yaml}"

case "${WORKFLOW}" in
  snapshot) ARTIFACT_HOST="https://artifacts-snapshot.elastic.co" ;;
  staging)  ARTIFACT_HOST="https://artifacts-staging.elastic.co" ;;
  *) echo "ERROR: unknown workflow '${WORKFLOW}', expected snapshot or staging" >&2; exit 1 ;;
esac

# Read dependency list from config file
mapfile -t DEPS < <(grep '^ *- ' "${DEPS_CONFIG}" | sed 's/^ *- //')

echo "--- :package: Merging DRA manifests for branch=${BRANCH} workflow=${WORKFLOW}"
echo "Dependencies: ${DEPS[*]}"

PROJECTS_JSON="{}"

for dep in "${DEPS[@]}"; do
  latest_url="${ARTIFACT_HOST}/${dep}/latest/${BRANCH}.json"
  echo "Fetching latest pointer for ${dep}: ${latest_url}"

  latest_json=$(curl -sf --retry 5 --retry-delay 5 --retry-all-errors "${latest_url}") || {
    echo "ERROR: failed to fetch latest pointer for ${dep} from ${latest_url}" >&2
    exit 1
  }

  manifest_url=$(echo "${latest_json}" | jq -r '.manifest_url')
  if [[ -z "${manifest_url}" || "${manifest_url}" == "null" ]]; then
    echo "ERROR: no manifest_url in latest pointer for ${dep}" >&2
    exit 1
  fi

  version=$(echo "${latest_json}" | jq -r '.version')
  build_id=$(echo "${latest_json}" | jq -r '.build_id')

  echo "  ${dep}: version=${version} build_id=${build_id}"

  # Add this product's entry to the projects map.
  # The packaging code reads external_artifacts_manifest_url to find artifacts.
  PROJECTS_JSON=$(echo "${PROJECTS_JSON}" | jq \
    --arg dep "${dep}" \
    --arg manifest_url "${manifest_url}" \
    --arg build_id "${build_id}" \
    '.[$dep] = {external_artifacts_manifest_url: $manifest_url, build_id: $build_id}')
done

# Write the merged manifest
jq -n \
  --argjson projects "${PROJECTS_JSON}" \
  --arg branch "${BRANCH}" \
  --arg workflow "${WORKFLOW}" \
  '{
    version: "merged",
    branch: $branch,
    workflow: $workflow,
    projects: $projects
  }' > "${OUTPUT_FILE}"

echo "Merged manifest written to ${OUTPUT_FILE}"
cat "${OUTPUT_FILE}"
