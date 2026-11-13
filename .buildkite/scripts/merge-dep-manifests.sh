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
IFS=$'\n' read -r -d '' -a DEPS < <(grep '^ *- ' "${DEPS_CONFIG}" | sed 's/^ *- //' && printf '\0')

echo "--- :package: Merging DRA manifests for branch=${BRANCH} workflow=${WORKFLOW}"
echo "Dependencies: ${DEPS[*]}"

PROJECTS_JSON="{}"
STACK_VERSION=""

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
  [[ -z "${STACK_VERSION}" ]] && STACK_VERSION="${version}"

  # Fetch the dep's full manifest and inline its projects.
  # The packaging code (manifest.go DownloadComponents) only downloads the single
  # merged manifest and looks up packages inline in projects[spec.ProjectName].
  # It does NOT follow external_artifacts_manifest_url — packages must be inlined.
  echo "  Fetching manifest for ${dep}: ${manifest_url}"
  dep_manifest=$(curl -sf --retry 5 --retry-delay 5 --retry-all-errors "${manifest_url}") || {
    echo "ERROR: failed to fetch manifest for ${dep} from ${manifest_url}" >&2
    exit 1
  }

  # Merge all projects from the dep manifest into PROJECTS_JSON.
  # This inlines packages for every project the dep publishes (e.g. beats publishes
  # beats, filebeat, metricbeat, etc.) so the packaging code can find them by name.
  # The dep's project entries already carry build_id, which the poller uses for
  # change detection via .projects[$dep].build_id.
  dep_projects=$(echo "${dep_manifest}" | jq '.projects // {}')
  PROJECTS_JSON=$(echo "${PROJECTS_JSON}" | jq --argjson dp "${dep_projects}" '. * $dp')
done

if [[ -z "${STACK_VERSION}" ]]; then
  echo "ERROR: could not determine stack version from dependencies" >&2
  exit 1
fi

# Write the merged manifest
jq -n \
  --argjson projects "${PROJECTS_JSON}" \
  --arg branch "${BRANCH}" \
  --arg workflow "${WORKFLOW}" \
  --arg version "${STACK_VERSION}" \
  '{
    version: $version,
    branch: $branch,
    workflow: $workflow,
    projects: $projects
  }' > "${OUTPUT_FILE}"

echo "Merged manifest written to ${OUTPUT_FILE}"
cat "${OUTPUT_FILE}"
