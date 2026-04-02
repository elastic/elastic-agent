#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# This script is not only used by integration CI, but also the agentless release pipeline to build the docker images
# that get released to serverless. USE_PACKAGE_VERSION is important here for both CI and agentless, as it validates
# that the components bundled to serverless are the same components that the CI validated.
#
# Making a change here can affect the released images to agentless, so be cautious.

export SNAPSHOT="true"
export EXTERNAL="true"
export USE_PACKAGE_VERSION="true"
export WINDOWS_NPCAP="true" # build Windows/amd64 with npcap bundled

mage package
