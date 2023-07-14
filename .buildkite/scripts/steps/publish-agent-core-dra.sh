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
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID_SECRET}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli collect \
        --project elastic-agent-core \
        --branch "${BRANCH}" \
        --commit "${BUILDKITE_COMMIT}" \
        --workflow "${WORKFLOW}" \
        --version "${BEAT_VERSION}" \
        --artifact-set agent-core \
        $dry_run
}

buildkite-agent artifact download "build/**/*" .

run_release_manager
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
