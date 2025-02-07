#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

<<<<<<< HEAD
PACKAGES=tar.gz,zip,rpm,deb PLATFORMS=linux/amd64,linux/arm64,windows/amd64  SNAPSHOT=true EXTERNAL=true  mage package
=======
# Remove AGENT_PACKAGE_VERSION pinning as soon as 9.0.0 is released
export AGENT_PACKAGE_VERSION=9.0.0

export SNAPSHOT="true"
export EXTERNAL="true"

mage package
>>>>>>> e956b4d2d (Split packaging into separate steps (#6401))
