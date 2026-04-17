#!/bin/bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

mage clean

# Two modes, matching the pre-unification packageUsingDRA behaviour:
#   - MANIFEST_URL passed in (real DRA packaging of already-published core):
#     download the core from the manifest, don't rebuild it.
#   - MANIFEST_URL not passed in (PR/branch build): compile the core from the
#     current checkout so packaging breakage in the PR is actually caught.
#     USE_PACKAGE_VERSION=true causes the settings loader to read
#     .package-version and set both ManifestURL and Snapshot=true.
if test -z "${MANIFEST_URL:-}"; then
  export AGENT_CORE_SOURCE=local
  export USE_PACKAGE_VERSION=true
else
  export AGENT_CORE_SOURCE=manifest
  export USE_PACKAGE_VERSION=false
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p "$AGENT_DROP_PATH"

MAGE_TARGETS=("package")
if [ "$FIPS" != "true" ]; then
  # Build helm package only on non-FIPS builds
  MAGE_TARGETS+=("helm:package")
  # Build ironbank only on non-FIPS builds
  MAGE_TARGETS+=("ironbank")
fi
MAGE_TARGETS+=("fixDRADockerArtifacts")

# Package and fix the DRA artifacts
mage "${MAGE_TARGETS[@]}"

echo  "+++ Generate dependencies report"
# The deps-report step needs the manifest URL at shell level. When the
# pipeline passed it in, we have it; otherwise read it from .package-version
# ourselves (mage already did the same internally via USE_PACKAGE_VERSION).
REPORT_MANIFEST_URL="${MANIFEST_URL:-$(jq -r .manifest_url .package-version)}"
BEAT_VERSION_FULL=$(curl -s -XGET "${REPORT_MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
