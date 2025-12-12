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

set -euo pipefail

PRIVATE_REPO="docker.elastic.co/observability-ci/ecp-elastic-agent-service"
REQUIRED_ARCHITECTURES=("amd64" "arm64")

_SELF=$(dirname "$0")
source "${_SELF}/../common.sh"

if [ -z "$SERVICE_VERSION" ]; then
    echo "SERVICE_VERSION environment variable is not set"
    exit 1
fi

DOCKER_TAG="git-${SERVICE_VERSION}"
PRIVATE_IMAGE="${PRIVATE_REPO}:${DOCKER_TAG}"

echo "Commit SHA: ${SERVICE_VERSION}"
echo "Validating image: ${PRIVATE_IMAGE}"

# Inspect the manifest to get architecture information
echo "--- :mag: Inspecting image manifest"
MANIFEST_OUTPUT=$(skopeo inspect docker://"${PRIVATE_IMAGE}" --raw 2>&1) || {
    echo "Failed to inspect manifest for image: ${PRIVATE_IMAGE}"
    echo "Error: ${MANIFEST_OUTPUT}"
    exit 1
}

echo "Manifest retrieved successfully"

# Extract architectures from the manifest
FOUND_ARCHITECTURES=$(echo "$MANIFEST_OUTPUT" | jq -r '.manifests[]?.platform.architecture // empty' | sort -u)

if [ -z "$FOUND_ARCHITECTURES" ]; then
    echo "No architectures found in manifest. This might be a single-architecture image."
    echo "Manifest content:"
    echo "$MANIFEST_OUTPUT" | jq .
    exit 1
fi

echo "Found architectures in image:"
echo "$FOUND_ARCHITECTURES"

# Validate that all required architectures are present
echo "--- :white_check_mark: Validating required architectures"
MISSING_ARCHITECTURES=()

for arch in "${REQUIRED_ARCHITECTURES[@]}"; do
    if echo "$FOUND_ARCHITECTURES" | grep -qw "$arch"; then
        echo "✓ Architecture '$arch' is present"
    else
        echo "✗ Architecture '$arch' is MISSING"
        MISSING_ARCHITECTURES+=("$arch")
    fi
done

if [ ${#MISSING_ARCHITECTURES[@]} -gt 0 ]; then
    echo ""
    echo "ERROR: Image ${PRIVATE_IMAGE} is missing required architectures: ${MISSING_ARCHITECTURES[*]}"
    exit 1
fi

echo ""
echo "SUCCESS: Image ${PRIVATE_IMAGE} contains all required architectures (${REQUIRED_ARCHITECTURES[*]})"

