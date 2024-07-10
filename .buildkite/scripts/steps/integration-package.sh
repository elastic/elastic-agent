#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

AGENT_PACKAGE_VERSION="$(cat .package-version)"
DEV=true 
EXTERNAL=true 
SNAPSHOT=true 
PLATFORMS=linux/amd64,linux/arm64,windows/amd64 
PACKAGES=tar.gz,zip,rpm,deb 

mage package
