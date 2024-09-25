#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

PACKAGES=tar.gz,zip,rpm,deb PLATFORMS=linux/amd64,linux/arm64,windows/amd64  SNAPSHOT=true EXTERNAL=true  mage package
