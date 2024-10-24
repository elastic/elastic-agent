#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

export AGENT_PACKAGE_VERSION=8.16.0
export PACKAGES=tar.gz,zip,rpm,deb

if [[ -n "PLATFORMS" ]]; then
    export PLATFORMS=linux/amd64,linux/arm64,windows/amd64
fi

SNAPSHOT=true EXTERNAL=true DEV=true mage package
