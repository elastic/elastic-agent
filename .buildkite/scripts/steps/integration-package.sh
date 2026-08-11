#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# SNAPSHOT=true, EXTERNAL=true and USE_PACKAGE_VERSION=true, previously
# exported here, are now the defaults: components come from the manifest
# pinned in .package-version, matching what CI validates.

mage package
