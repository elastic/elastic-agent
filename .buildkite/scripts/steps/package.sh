#!/usr/bin/env bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

mage clean

# Default behavior (no MANIFEST_URL): compile core from this checkout and read
# version/snapshot from .package-version (AGENT_CORE_SOURCE=local and
# USE_PACKAGE_VERSION=true are both defaults). When MANIFEST_URL is provided
# (DRA full-package run), download core from the manifest instead.
if [ -n "${MANIFEST_URL:-}" ]; then
  export AGENT_CORE_SOURCE=manifest
  export USE_PACKAGE_VERSION=false
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p "$AGENT_DROP_PATH"

MAGE_TARGETS=("package")
if [ "$FIPS" != "true" ]; then
  MAGE_TARGETS+=("helm:package")
  MAGE_TARGETS+=("ironbank")
fi
MAGE_TARGETS+=("fixDRADockerArtifacts")

mage "${MAGE_TARGETS[@]}"

echo "+++ Generate dependencies report"
# When the pipeline set MANIFEST_URL we already have it; otherwise read it from
# .package-version (mage did the same internally via USE_PACKAGE_VERSION).
REPORT_MANIFEST_URL="${MANIFEST_URL:-$(jq -r .manifest_url .package-version)}"
BEAT_VERSION_FULL=$(curl -s -XGET "${REPORT_MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
