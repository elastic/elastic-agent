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

BUILD_VERSION="$(jq -r '.version' .package-version)"
DOCKER_TAG="git-${VERSION}"
PRIVATE_REPO="docker.elastic.co/observability-ci/ecp-elastic-agent-service"
PRIVATE_IMAGE="${PRIVATE_REPO}:${DOCKER_TAG}"

# download the amd64 and arm64 builds of the image from the previous steps
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-amd64"
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-arm64"

# AMD64
docker load -i ./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-amd64.docker.tar.gz
docker image tag "elastic-agent-service:$DOCKER_TAG" "$PRIVATE_IMAGE"
docker push "$PRIVATE_IMAGE"
AMD64_DIGEST=$(docker image inspect --format "{{index .RepoDigests 0}}" "$PRIVATE_IMAGE")

# ARM64 (overwrites AMD64 tags)
docker load -i ./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-arm64.docker.tar.gz
docker image tag "elastic-agent-service:$DOCKER_TAG" "$PRIVATE_IMAGE"
docker push "$PRIVATE_IMAGE"
ARM64_DIGEST=$(docker image inspect --format "{{index .RepoDigests 0}}" "$PRIVATE_IMAGE")

# at this point the $PRIVATE_IMAGE is pointing to only the arm64 based image, we need the image to
# be a multi-architecture based image so we create an image from the digests and tag it the same and
# push it to the registry (aka. make the tag now a multi-architecture based image)
docker buildx imagetools create -t "$PRIVATE_IMAGE" \
  "$AMD64_DIGEST" \
  "$ARM64_DIGEST"
docker push "$PRIVATE_IMAGE"

annotate "* Image: $PRIVATE_IMAGE"
annotate "* Short commit: $VERSION"
annotate "* Commit: https://github.com/elastic/elastic-agent/commit/$VERSION"

buildkite-agent meta-data set "git-short-commit" "$VERSION"

write_annotation
