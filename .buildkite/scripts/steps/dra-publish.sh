#!/usr/bin/env bash

set -euo pipefail

DRY_RUN="${DRA_DRY_RUN:=""}"
WORKFLOW="${DRA_WORKFLOW:=""}"
COMMIT="${DRA_COMMIT:="${BUILDKITE_COMMIT:=""}"}"
BRANCH="${DRA_BRANCH:="${BUILDKITE_BRANCH:=""}"}"
PACKAGE_VERSION="${DRA_VERSION:="${BEAT_VERSION:=""}"}"
VERSION_QUALIFIER="${VERSION_QUALIFIER:=""}"

# force main branch on PR's or it won't execute
# because the PR branch does not have a project folder in release-manager
if [[ "${BUILDKITE_PULL_REQUEST:="false"}" != "false" ]]; then
    BRANCH=main
    DRY_RUN="--dry-run"
    echo "+++ Running in PR and setting branch main and --dry-run"
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

function run_release_manager() {
    local _command="${1}" _project_id="${2}" _artifact_set="${3}" _workflow="${4}" _commit="${5}" _branch="${6}" _version="${7}" _dry_run="${8:-""}"
    echo "+++ :hammer_and_pick: Release manager ${_command} ${_branch} ${_workflow} ${_dry_run} DRA artifacts..."
    # shellcheck disable=SC2086
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR_SECRET}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli "${_command}" \
        --project "${_project_id}" \
        --branch "${_branch}" \
        --commit "${_commit}" \
        --workflow "${_workflow}" \
        --version "${_version}" \
        --artifact-set "${_artifact_set}" \
        --qualifier "${VERSION_QUALIFIER}" \
        ${_dry_run}
}

echo "~~~ Fetch Release Manager Docker image"
docker pull docker.elastic.co/infra/release-manager:latest

echo "+++ Release Manager Workflow: ${WORKFLOW} / Branch: ${BRANCH} / VERSION_QUALIFIER: ${VERSION_QUALIFIER} / Commit: ${COMMIT}"
run_release_manager "list" "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW}" "${COMMIT}" "${BRANCH}" "${PACKAGE_VERSION}"
run_release_manager "collect" "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW}" "${COMMIT}" "${BRANCH}" "${PACKAGE_VERSION}" "${DRY_RUN}"
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
