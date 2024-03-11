#!/usr/bin/env bash

set -euo pipefail

# This file is a temporary workaround for the Independent Agent Release
# workflow.  The ironbank docker image does not currently handle the
# AGENT_PACKAGE_VERSION env var override.  This renames that file
# to use that new version.
#
# We will not (at first) be using the ironbank docker image in the 
# Independent Agent releases; however, we want to use the release-manager
# container dry-run as a check that all the expected images exist.
#
# This workaround allows the check to proceed without erroring on the file
# that we know won't be named correctly.
#

PACKAGE_VERSION="${AGENT_PACKAGE_VERSION:=""}"

if [[ -z "${PACKAGE_VERSION}" ]]; then 
    echo "AGENT_PACKAGE_VERSION is not set, exiting"
    exit 1
fi

IRONBANK_DOCKER_BLOB_PREFIX="elastic-agent-ironbank"
IRONBANK_DOCKER_BLOB_SUFFIX="docker-build-context.tar.gz"
OUTPUT_DIRNAME="build/distributions"

echo "--- ls ${OUTPUT_DIRNAME}"
ls -al "${OUTPUT_DIRNAME}"
echo "--- ironbank expected path"
echo "${OUTPUT_DIRNAME}"/"${IRONBANK_DOCKER_BLOB_PREFIX}"*"${IRONBANK_DOCKER_BLOB_SUFFIX}"
ls -al "${OUTPUT_DIRNAME}"/"${IRONBANK_DOCKER_BLOB_PREFIX}"*"${IRONBANK_DOCKER_BLOB_SUFFIX}" || true

echo "--- looking for ironbank file to copy to new name"
if ls "${OUTPUT_DIRNAME}"/"${IRONBANK_DOCKER_BLOB_PREFIX}"*"${IRONBANK_DOCKER_BLOB_SUFFIX}" 2>/dev/null; then 
    # Found the ironbank file
    echo "Found the ironbank file"
    NEW_IRONBANK_NAME="elastic-agent-ironbank-${PACKAGE_VERSION}-docker-build-context.tar.gz"
    echo "Copying to new path: ${OUTPUT_DIRNAME}/${NEW_IRONBANK_NAME}"
    cp "${OUTPUT_DIRNAME}"/"${IRONBANK_DOCKER_BLOB_PREFIX}"*"${IRONBANK_DOCKER_BLOB_SUFFIX}" "${OUTPUT_DIRNAME}/${NEW_IRONBANK_NAME}"
else
    echo "Error: could not find ironbank file"
    exit 1
fi
