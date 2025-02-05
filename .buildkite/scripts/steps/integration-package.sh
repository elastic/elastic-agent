#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh
# Remove AGENT_PACKAGE_VERSION pinning as soon as 9.0.0 is released
AGENT_PACKAGE_VERSION=9.0.0 PACKAGES=tar.gz,zip,rpm,deb PLATFORMS=linux/amd64,linux/arm64,windows/amd64  SNAPSHOT=true EXTERNAL=true  mage package
