#!/bin/bash

set -uo pipefail

source .buildkite/scripts/bootstrap.sh

# Publish DRA artifacts
function run_release_manager() {
    echo "+++ Publishing $BUILDKITE_BRANCH ${WORKFLOW} DRA artifacts..."
    dry_run=""
    if [ "$BUILDKITE_PULL_REQUEST" != "false" ]; then
        dry_run="--dry-run"
        # force main branch on PR's or it won't execute
        # because the PR branch does not have a project folder in release-manager
        BRANCH=main
    fi
    if [ "$FORCE_NO_DRA_DRY_RUN" == "true" ]; then
        dry_run=""
    fi
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR_SECRET}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli collect \
        --project $DRA_PROJECT \
        --branch "${BRANCH}" \
        --commit "${BUILDKITE_COMMIT}" \
        --workflow "${WORKFLOW}" \
        --version "${BEAT_VERSION}" \
        --artifact-set $DRA_ARTIFACT_SET \
        $dry_run
}

chmod -R 777 build/distributions

run_release_manager
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
