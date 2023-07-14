#!/bin/bash

set -uo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

# Publish DRA artifacts
function run_release_manager() {
    local PROJECT_ID="${1}" PROJECT_ARTIFACT_ID="${2}" WORKFLOW="${3}" DRY_RUN="${4}"
    if [[ -z "${WORKFLOW}" ]]; then
      echo "+++ Missing DRA workflow";
      exit 1
    fi
    if [[ -z "${BUILDKITE_COMMIT:-""}" ]]; then
      echo "+++ Missing git commit sha";
      exit 1
    fi
    if [[ -z "${BEAT_VERSION:-""}" ]]; then
      echo "+++ Missing BEAT_VERSION";
      exit 1
    fi

    echo "+++ :hammer_and_pick: Publishing $BUILDKITE_BRANCH ${WORKFLOW} DRA artifacts..."
    if [ "$BUILDKITE_PULL_REQUEST" != "false" ]; then
        # force main branch on PR's or it won't execute
        # because the PR branch does not have a project folder in release-manager
        BRANCH=main
    fi
    echo docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR_DRA}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli collect \
        --project "${PROJECT_ID}" \
        --branch "${BRANCH}" \
        --commit "${BUILDKITE_COMMIT}" \
        --workflow "${WORKFLOW}" \
        --version "${BEAT_VERSION}" \
        --artifact-set "${PROJECT_ARTIFACT_ID}" \
        "${DRY_RUN}"
}

DRA_DRY_RUN="${DRA_DRY_RUN:="--dry-run"}"
run_release_manager "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW:=""}" "${DRA_DRY_RUN}"
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
