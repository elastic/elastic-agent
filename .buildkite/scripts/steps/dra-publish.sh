#!/bin/bash

set -uo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

# Publish DRA artifacts
function run_release_manager() {
    local PROJECT_ID="${1}" PROJECT_ARTIFACT_ID="${2}" WORKFLOW="${3}" COMMIT="${4}" BRANCH="${5}" DRY_RUN="${6}"
    if [[ -z "${WORKFLOW}" ]]; then
      echo "+++ Missing DRA workflow";
      exit 1
    fi
    if [[ -z "${COMMIT:-""}" ]]; then
      echo "+++ Missing git commit sha";
      exit 1
    fi
    if [[ -z "${BEAT_VERSION:-""}" ]]; then
      echo "+++ Missing BEAT_VERSION";
      exit 1
    fi
    if [[ -z "${BRANCH:-""}" ]]; then
          echo "+++ Missing BRANCH";
          exit 1
        fi

    echo "+++ :hammer_and_pick: Publishing $BUILDKITE_BRANCH ${WORKFLOW} DRA artifacts..."
    if [ "$BUILDKITE_PULL_REQUEST" != "false" ]; then
        # force main branch on PR's or it won't execute
        # because the PR branch does not have a project folder in release-manager
        BRANCH=main
        DRY_RUN="--dry-run"
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
        --commit "${COMMIT}" \
        --workflow "${WORKFLOW}" \
        --version "${BEAT_VERSION}" \
        --artifact-set "${PROJECT_ARTIFACT_ID}" \
        "${DRY_RUN}"
}

DRA_DRY_RUN="${DRA_DRY_RUN:="--dry-run"}"
WORKFLOW="${DRA_WORKFLOW:=""}"
COMMIT="${DRA_COMMIT:=""}"
BRANCH="${DRA_BRANCH:=""}"

if [[ -z "${WORKFLOW:=""}" ]]; then
  if [[ "${ManifestURL}" =~ "staging" ]]; then
    WORKFLOW="staging"
  fi
  if [[ "${ManifestURL}" =~ "snapshots" ]]; then
    WORKFLOW="snapshot"
  fi
fi
echo "+++ Release Manager ${WORKFLOW} / ${BRANCH} / ${COMMIT}";
run_release_manager "${DRA_PROJECT_ID}" "${DRA_PROJECT_ARTIFACT_ID}" "${WORKFLOW:=""}" "${COMMIT}" "${BRANCH}" "${DRA_DRY_RUN}"

RM_EXIT_CODE=$?
exit $RM_EXIT_CODE
