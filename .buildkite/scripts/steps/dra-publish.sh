#!/bin/bash

set -euo pipefail

WORKFLOW="${DRA_WORKFLOW:=""}"
COMMIT="${DRA_COMMIT:="${BUILDKITE_COMMIT:=""}"}"
BRANCH="${DRA_BRANCH:="${BUILDKITE_BRANCH:=""}"}"
PACKAGE_VERSION="${DRA_VERSION:="${BEAT_VERSION:=""}"}"
VERSION_QUALIFIER="${VERSION_QUALIFIER:=""}"

if [[ "${DRA_DRY_RUN:="false"}" == "true" ]]; then
  echo "~~~ Running in dry-run mode -- will NOT publish artifacts"
  DRY_RUN="--dry-run"
else
  echo "~~~ Running in publish mode"
  DRY_RUN=""
fi

if [[ -z "${WORKFLOW}" ]]; then
  echo "+++ Missing DRA workflow";
  exit 1
fi
if [[ -z "${COMMIT:-""}" ]]; then
  echo "+++ Missing DRA_COMMIT";
  exit 1
fi
if [[ -z "${PACKAGE_VERSION:-""}" ]]; then
  echo "+++ Missing DRA_VERSION";
  exit 1
fi
if [[ -z "${BRANCH:-""}" ]]; then
  echo "+++ Missing DRA_BRANCH";
  exit 1
fi

# Listing Release manager
function run_release_manager_list() {
    local _project_id="${1}" _artifact_set="${2}" _workflow="${3}" _commit="${4}" _branch="${5}" _version="${6}"
    echo "+++ :hammer_and_pick: Release manager listing ${_branch} ${_workflow} DRA artifacts..."
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR_SECRET}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli list \
        --project "${_project_id}" \
        --branch "${_branch}" \
        --commit "${_commit}" \
        --workflow "${_workflow}" \
        --version "${_version}" \
        --artifact-set "${_artifact_set}" \
        --qualifier "${VERSION_QUALIFIER}"
}

# Publish DRA artifacts
function run_release_manager_collect() {
    local _project_id="${1}" _artifact_set="${2}" _workflow="${3}" _commit="${4}" _branch="${5}" _version="${6}" _dry_run="${7}"
    echo "+++ :hammer_and_pick: Publishing ${_branch} ${_workflow} DRA artifacts..."
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR_SECRET}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli collect \
        --project "${_project_id}" \
        --branch "${_branch}" \
        --commit "${_commit}" \
        --workflow "${_workflow}" \
        --version "${_version}" \
        --artifact-set "${_artifact_set}" \
        --qualifier "${VERSION_QUALIFIER}" \
        ${_dry_run}
}

echo "+++ Release Manager Workflow: ${WORKFLOW} / Branch: ${BRANCH} / VERSION_QUALIFIER: ${VERSION_QUALIFIER} / Commit: ${COMMIT}"
run_release_manager_list "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW}" "${COMMIT}" "${BRANCH}" "${PACKAGE_VERSION}"
run_release_manager_collect "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW}" "${COMMIT}" "${BRANCH}" "${PACKAGE_VERSION}" "${DRY_RUN}"
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
