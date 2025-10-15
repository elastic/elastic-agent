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

echo "--- :package: Preparing build information"
BUILD_VERSION="$(jq -r '.version' .package-version)"
DOCKER_TAG="git-${VERSION}"
PRIVATE_REPO="docker.elastic.co/observability-ci/ecp-elastic-agent-service"
PRIVATE_IMAGE="${PRIVATE_REPO}:${DOCKER_TAG}"

echo "Build version: ${BUILD_VERSION}"
echo "Docker tag: ${DOCKER_TAG}"
echo "Target image: ${PRIVATE_IMAGE}"

echo "--- :arrow_down: Downloading build artifacts"
echo "Downloading AMD64 build artifacts..."
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-amd64"
echo "Downloading ARM64 build artifacts..."
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-arm64"

echo "--- :docker: Processing AMD64 image"
echo "Loading AMD64 image..."
docker load -i ./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-amd64.docker.tar.gz
echo "Tagging AMD64 image as ${PRIVATE_IMAGE}..."
docker image tag "elastic-agent-service:$DOCKER_TAG" "$PRIVATE_IMAGE"
echo "Pushing AMD64 image..."
docker push "$PRIVATE_IMAGE"
AMD64_DIGEST=$(docker image inspect --format "{{index .RepoDigests 0}}" "$PRIVATE_IMAGE")
echo "AMD64 digest: ${AMD64_DIGEST}"

echo "--- :docker: Processing ARM64 image"
echo "Loading ARM64 image..."
docker load -i ./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-arm64.docker.tar.gz
echo "Tagging ARM64 image as ${PRIVATE_IMAGE}..."
docker image tag "elastic-agent-service:$DOCKER_TAG" "$PRIVATE_IMAGE"
echo "Pushing ARM64 image..."
docker push "$PRIVATE_IMAGE"
ARM64_DIGEST=$(docker image inspect --format "{{index .RepoDigests 0}}" "$PRIVATE_IMAGE")
echo "ARM64 digest: ${ARM64_DIGEST}"

echo "--- :rocket: Creating multi-architecture manifest"
echo "Creating multi-arch image from digests..."
docker buildx imagetools create -t "$PRIVATE_IMAGE" \
  "$AMD64_DIGEST" \
  "$ARM64_DIGEST"
echo "Multi-architecture image created and pushed successfully"

echo "--- :memo: Creating build annotation and metadata"
annotate "* Image: $PRIVATE_IMAGE"
annotate "* Short commit: $VERSION"
annotate "* Commit: https://github.com/elastic/elastic-agent/commit/$VERSION"

buildkite-agent meta-data set "git-short-commit" "$VERSION"

write_annotation
