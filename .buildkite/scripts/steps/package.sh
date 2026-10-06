#!/usr/bin/env bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

# Default behavior (no MANIFEST_URL): compile core from this checkout and read
# version/snapshot from .package-version (the `package` target reads it by
# default). When MANIFEST_URL is provided (DRA full-package run), the manifest
# is authoritative instead: download core from it and skip .package-version.
if [ -n "${MANIFEST_URL:-}" ]; then
  export AGENT_CORE_SOURCE=manifest
fi

mage clean

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
# .package-version (the package target read the same file internally).
REPORT_MANIFEST_URL="${MANIFEST_URL:-$(jq -r .manifest_url .package-version)}"
BEAT_VERSION_FULL=$(curl -sf --retry 5 --retry-delay 5 --retry-all-errors -XGET "${REPORT_MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
