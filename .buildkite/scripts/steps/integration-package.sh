#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

export SNAPSHOT="true"
export EXTERNAL="true"

if [[ -f .package-version ]]; then
  MANIFEST_URL=$(jq -r '.manifest_url' .package-version)
  export MANIFEST_URL
  echo "set MANIFEST_URL=$MANIFEST_URL (from .package-version)"
fi

mage package
