#!/usr/bin/env bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

<<<<<<< HEAD
if test -z "${MANIFEST_URL=:""}"; then
  echo "Missing variable MANIFEST_URL, export it before use."
  exit 2
fi

=======
# Default behavior (no MANIFEST_URL): compile core from this checkout and read
# version/snapshot from .package-version (AGENT_CORE_SOURCE=local and
# USE_PACKAGE_VERSION=true are both defaults). When MANIFEST_URL is provided
# (DRA full-package run), download core from the manifest instead.
if [ -n "${MANIFEST_URL:-}" ]; then
  export AGENT_CORE_SOURCE=manifest
  export USE_PACKAGE_VERSION=false
fi

mage clean

>>>>>>> dce51a67b ([mage] Unify packaging targets (#14871))
export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p "$AGENT_DROP_PATH"

<<<<<<< HEAD
MAGE_TARGETS=(clean downloadManifest packageUsingDRA)
=======
MAGE_TARGETS=("package")
>>>>>>> dce51a67b ([mage] Unify packaging targets (#14871))
if [ "$FIPS" != "true" ]; then
  MAGE_TARGETS+=("helm:package")
  MAGE_TARGETS+=("ironbank")
fi
MAGE_TARGETS+=("fixDRADockerArtifacts")

<<<<<<< HEAD
# Download the components from the MANIFEST_URL and then package those downloaded into the $AGENT_DROP_PATH
mage "${MAGE_TARGETS[@]}"

echo  "+++ Generate dependencies report"
BEAT_VERSION_FULL=$(curl -s -XGET "${MANIFEST_URL}" |jq '.version' -r )
=======
mage "${MAGE_TARGETS[@]}"

echo "+++ Generate dependencies report"
# When the pipeline set MANIFEST_URL we already have it; otherwise read it from
# .package-version (mage did the same internally via USE_PACKAGE_VERSION).
REPORT_MANIFEST_URL="${MANIFEST_URL:-$(jq -r .manifest_url .package-version)}"
BEAT_VERSION_FULL=$(curl -sf --retry 5 --retry-delay 5 --retry-all-errors -XGET "${REPORT_MANIFEST_URL}" |jq '.version' -r )
>>>>>>> dce51a67b ([mage] Unify packaging targets (#14871))
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
