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

IRONBANK_DOCKER_BLOB="elastic-agent-ironbank-*-docker-build-context.tar.gz"
OUTPUT_DIRNAME="build/distributions"

if ls "${OUTPUT_DIRNAME}/${IRONBANK_DOCKER_BLOB}" 2>/dev/null; then 
    # Found the ironbank file
    NEW_IRONBANK_NAME="elastic-agent-ironbank-${PACKAGE_VERSION}-docker-build-context.tar.gz"
    cp "${OUTPUT_DIRNAME}/${IRONBANK_DOCKER_BLOB}" "${OUTPUT_DIRNAME}/${NEW_IRONBANK_NAME}"
else
    echo "Error: could not find ironbank file"
    exit 1
fi
