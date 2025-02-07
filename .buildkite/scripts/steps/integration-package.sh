#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# Remove AGENT_PACKAGE_VERSION pinning as soon as 9.0.0 is released
export AGENT_PACKAGE_VERSION=9.0.0

export SNAPSHOT="true"
export EXTERNAL="true"

mage package
