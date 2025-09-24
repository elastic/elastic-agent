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

# TODO: let's avoid accessing vault directly but use the vault plugin itself
#       https://github.com/elastic/vault-docker-login-buildkite-plugin does not support
#       the `skopeo` command by default but looks for the current installed tools in the runner
#       Let's contribute in a follow-up PR to support `skopeo` as well.
DOCKER_REGISTRY_SECRET_PATH="kv/ci-shared/platform-ingest/docker_registry_prod"
DOCKER_REGISTRY="docker.elastic.co"
DOCKER_USERNAME_SECRET=$(retry 5 vault kv get -field user "${DOCKER_REGISTRY_SECRET_PATH}")
DOCKER_PASSWORD_SECRET=$(retry 5 vault kv get -field password "${DOCKER_REGISTRY_SECRET_PATH}")
skopeo login --username "${DOCKER_USERNAME_SECRET}" --password "${DOCKER_PASSWORD_SECRET}" "${DOCKER_REGISTRY}"

# download manifest-tool if not available (lightweight manifest creation tool)
echo "--- Downloading manifest-tool"
if ! command -v manifest-tool &> /dev/null; then
    MANIFEST_TOOL_VERSION="2.2.0"
    
    # Detect current architecture
    case "$(uname -m)" in
        x86_64) MANIFEST_TOOL_ARCH="amd64" ;;
        aarch64|arm64) MANIFEST_TOOL_ARCH="arm64" ;;
        armv7l) MANIFEST_TOOL_ARCH="armv7" ;;
        *) echo "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    echo "--- Downloading manifest-tool v${MANIFEST_TOOL_VERSION} for ${MANIFEST_TOOL_ARCH}"
    curl -L "https://github.com/estesp/manifest-tool/releases/download/v${MANIFEST_TOOL_VERSION}/binaries-manifest-tool-${MANIFEST_TOOL_VERSION}.tar.gz" | tar -xz "manifest-tool-linux-${MANIFEST_TOOL_ARCH}"
    mv "manifest-tool-linux-${MANIFEST_TOOL_ARCH}" manifest-tool
    chmod +x manifest-tool
    MANIFEST_TOOL_CMD="./manifest-tool"
else
    MANIFEST_TOOL_CMD="manifest-tool"
fi

manifest-tool --version

# download the amd64 and arm64 builds of the image from the previous steps
echo "--- Downloading amd64 and arm64 builds"
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-amd64"
buildkite-agent artifact download "build/distributions/**" . --step "packaging-service-container-arm64"

# get the digest information so the manifest reference the images
echo "--- Finding digests"
AMD64_DIGEST=$(skopeo inspect --format "{{.Digest}}" "docker-archive:./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-amd64.docker.tar.gz")
ARM64_DIGEST=$(skopeo inspect --format "{{.Digest}}" "docker-archive:./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-arm64.docker.tar.gz")

# copy the images into the private image location with digest (not tag)
echo "--- Copying images to private image location"
skopeo copy --all "docker-archive:./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-amd64.docker.tar.gz" "docker://$PRIVATE_REPO@$AMD64_DIGEST"
skopeo copy --all "docker-archive:./build/distributions/elastic-agent-service-$DOCKER_TAG-$BUILD_VERSION-linux-arm64.docker.tar.gz" "docker://$PRIVATE_REPO@$ARM64_DIGEST"

# Create a multi-arch manifest using manifest-tool
echo "--- Creating multi-arch manifest"

# Create a temporary YAML spec file for manifest-tool
cat > manifest-spec.yaml << EOF
image: $PRIVATE_IMAGE
manifests:
  -
    image: $PRIVATE_REPO@$AMD64_DIGEST
    platform:
      architecture: amd64
      os: linux
  -
    image: $PRIVATE_REPO@$ARM64_DIGEST
    platform:
      architecture: arm64
      os: linux
EOF

echo "Using manifest spec:"
cat manifest-spec.yaml

# Create and push the multi-arch manifest
$MANIFEST_TOOL_CMD --username ${DOCKER_USERNAME_SECRET} --password ${DOCKER_PASSWORD_SECRET} push from-spec manifest-spec.yaml

annotate "* Image: $PRIVATE_IMAGE"
annotate "* Short commit: $VERSION"
annotate "* Commit: https://github.com/elastic/elastic-agent/commit/$VERSION"

buildkite-agent meta-data set "git-short-commit" "$VERSION"

write_annotation
