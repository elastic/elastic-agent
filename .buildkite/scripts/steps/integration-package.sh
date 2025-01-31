#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

AGENT_STACK_VERSION="9.0.0-SNAPSHOT" PACKAGES=tar.gz,zip,rpm,deb PLATFORMS=linux/amd64,linux/arm64,windows/amd64  SNAPSHOT=true EXTERNAL=true  mage package
