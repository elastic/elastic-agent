#!/bin/bash

set -uo pipefail

.buildkite/scripts/bootstrap.sh

echo "+++ Setting DRA params"
# Shared secret path containing the dra creds for project teams
DRA_CREDS=$(vault kv get -field=data -format=json kv/ci-shared/release/dra-role)
VAULT_ADDR=$(echo $DRA_CREDS | jq -r '.vault_addr')
VAULT_ROLE_ID=$(echo $DRA_CREDS | jq -r '.role_id')
VAULT_SECRET_ID=$(echo $DRA_CREDS | jq -r '.secret_id')
export VAULT_ADDR VAULT_ROLE_ID VAULT_SECRET_ID

# Publish DRA artifacts
function run_release_manager() {
    echo "+++ Publishing $BUILDKITE_BRANCH ${WORKFLOW} DRA artifacts..."
    dry_run=""
    if [ "$BUILDKITE_PULL_REQUEST" != "false" ]; then
        dry_run="--dry-run"
    fi
    docker run --rm \
        --name release-manager \
        -e VAULT_ADDR="${VAULT_ADDR}" \
        -e VAULT_ROLE_ID="${VAULT_ROLE_ID}" \
        -e VAULT_SECRET_ID="${VAULT_SECRET_ID}" \
        --mount type=bind,readonly=false,src="${PWD}",target=/artifacts \
        docker.elastic.co/infra/release-manager:latest \
        cli collect \
        --project agent-core \
        --branch "${BRANCH}" \
        --commit "${BUILDKITE_COMMIT}" \
        --workflow "${WORKFLOW}" \
        --version "${BEAT_VERSION}" \
        --artifact-set main \
        $dry_run
}

run_release_manager
RM_EXIT_CODE=$?

exit $RM_EXIT_CODE
