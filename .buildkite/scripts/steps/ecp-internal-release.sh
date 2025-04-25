#!/usr/bin/env bash

# ELASTICSEARCH CONFIDENTIAL
# __________________
#
#  Copyright Elasticsearch B.V. All rights reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of Elasticsearch B.V. and its suppliers, if any.
# The intellectual and technical concepts contained herein
# are proprietary to Elasticsearch B.V. and its suppliers and
# may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright
# law.  Dissemination of this information or reproduction of
# this material is strictly forbidden unless prior written
# permission is obtained from Elasticsearch B.V.

set -eu

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"


# annotate create temp markdown file if not exists
# this file will be later used to annotate the build
# it appends to the file the message passed as argument
BUILDKITE_ANNOTATE_FILE="buildkite-annotate.md"
annotate() {
    echo "$1" >>$BUILDKITE_ANNOTATE_FILE
}

write_annotation() {
    cat $BUILDKITE_ANNOTATE_FILE | buildkite-agent annotate --style info
}

DOCKER_REGISTRY_SECRET_PATH="kv/ci-shared/platform-ingest/docker_registry_prod"
DOCKER_REGISTRY="docker.elastic.co"
PRIVATE_REPO="docker.elastic.co/observability-ci/ecp-elastic-agent-service"
SNAPSHOT_DRA_URL=https://snapshots.elastic.co/latest/master.json

DRA_RESULT=$(curl -s -X GET "$SNAPSHOT_DRA_URL")
echo "$DRA_RESULT"
BUILD_ID=$(echo "$DRA_RESULT" | jq '.build_id' | tr -d '"')
BUILD_VERSION=$(echo "$DRA_RESULT" | jq '.version' | tr -d '"')

MANIFEST_URL="https://snapshots.elastic.co/$BUILD_ID/agent-package/agent-artifacts-$BUILD_VERSION.json"
GIT_COMMIT=$(curl -s -X GET "$MANIFEST_URL" | jq '.projects["elastic-agent-core"]["commit_hash"]' | tr -d '"')
GIT_SHORT_COMMIT=$(echo "$GIT_COMMIT" | cut -c1-12)

DOCKER_TAG="git-${GIT_SHORT_COMMIT}"
PRIVATE_IMAGE="${PRIVATE_REPO}:${DOCKER_TAG}"

DOCKER_USERNAME_SECRET=$(retry 5 vault kv get -field user "${DOCKER_REGISTRY_SECRET_PATH}")
DOCKER_PASSWORD_SECRET=$(retry 5 vault kv get -field password "${DOCKER_REGISTRY_SECRET_PATH}")
skopeo login --username "${DOCKER_USERNAME_SECRET}" --password "${DOCKER_PASSWORD_SECRET}" "${DOCKER_REGISTRY}"
skopeo copy --all "docker://docker.elastic.co/cloud-release/elastic-agent-service:$BUILD_ID-SNAPSHOT" "docker://$PRIVATE_IMAGE"

annotate "* Image: $PRIVATE_IMAGE"
annotate "* Short commit: $GIT_SHORT_COMMIT"
annotate "* Commit: https://github.com/elastic/elastic-agent/commit/$GIT_COMMIT"
annotate "* Manifest: $MANIFEST_URL"

buildkite-agent meta-data set "git-short-commit" "$GIT_SHORT_COMMIT"

write_annotation
