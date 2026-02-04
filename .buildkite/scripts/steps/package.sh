#!/bin/bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

mage clean

if test -z "${MANIFEST_URL:-}"; then
  echo "No MANIFEST_URL building core packages"

  # Repo manifest is always SNAPSHOT components, force
  # building in SNAPSHOT mode.
  export SNAPSHOT=true

  # No manifest URL build the the core packages.
  mage packageAgentCore

  # Set manifest to version in repo so downloadManifest target
  # can download the needed components. This gets unset before
  # calling packageUsingDRA, so it uses the core built packages.
  export MANIFEST_URL=$(jq -r .manifest_url .package-version)
  _UNSET_MANIFEST_URL=true

  echo "Using MANIFEST_URL from .package-version"
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p $AGENT_DROP_PATH

mage downloadManifest

if [ "${_UNSET_MANIFEST_URL:-}" = "true" ]; then
  # Unset before calling packageUsingDRA this will have the target
  # use the built agent core packages from above
  unset MANIFEST_URL
fi

MAGE_TARGETS=("packageUsingDRA")
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
if test -z "${MANIFEST_URL:-}"; then
  # Ensure MANIFEST_URL is set. Would become unset above.
  MANIFEST_URL=$(jq -r .manifest_url .package-version)
fi
BEAT_VERSION_FULL=$(curl -s -XGET "${MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
