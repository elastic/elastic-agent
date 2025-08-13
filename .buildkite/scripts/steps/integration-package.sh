#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

export SNAPSHOT="true"
export EXTERNAL="true"
export USE_PACKAGE_VERSION="true"

mage package
