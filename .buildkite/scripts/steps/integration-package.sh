#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# This script is not only used by integration CI, but also the agentless release pipeline to build the docker images
# that get released to serverless. USE_PACKAGE_VERSION is important here for both CI and agentless, as it validates
# that the components bundled to serverless are the same components that the CI validated.
#
# Making a change here can affect the released images to agentless, so be cautious.

export USE_PACKAGE_VERSION="true" # loader sets ManifestURL, Snapshot=true, AgentDropPath from .package-version
export WINDOWS_NPCAP="true" # build Windows/amd64 with npcap bundled
# Compile elastic-agent-core from the current checkout. Integration tests
# (and the agentless release builds) are only meaningful if the core being
# exercised is the one from this commit; pin CoreSource so a pipeline-level
# env override cannot silently flip us to manifest-downloaded core.
export AGENT_CORE_SOURCE=local

mage package
