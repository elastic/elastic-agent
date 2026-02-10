#!/bin/bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

<<<<<<< HEAD
if test -z "${MANIFEST_URL=:""}"; then
  echo "Missing variable MANIFEST_URL, export it before use."
  exit 2
=======
mage clean

if test -z "${MANIFEST_URL:-}"; then
  echo "No MANIFEST_URL building core packages"

  # Repo manifest is always SNAPSHOT components, force
  # building in SNAPSHOT mode.
  export SNAPSHOT=true

  # We want to use the version from .package-version.
  # If the version defined in version/version.go is different,
  # the packaging step will expect artifacts with different names
  # than what the manifest contains
  export USE_PACKAGE_VERSION=true

  # No manifest URL build the the core packages.
  mage packageAgentCore

  # Set manifest to version in repo so downloadManifest target
  # can download the needed components. This gets unset before
  # calling packageUsingDRA, so it uses the core built packages.
  export MANIFEST_URL=$(jq -r .manifest_url .package-version)
  _UNSET_MANIFEST_URL=true

  echo "Using MANIFEST_URL from .package-version"
>>>>>>> 1d8207cca (Use agent version from .package-version in PR package step (#12660))
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p $AGENT_DROP_PATH

MAGE_TARGETS=(clean downloadManifest packageUsingDRA)
if [ "$FIPS" != "true" ]; then
  # Build helm package only on non-FIPS builds
  MAGE_TARGETS+=("helm:package")
  # Build ironbank only on non-FIPS builds
  MAGE_TARGETS+=("ironbank")
fi
MAGE_TARGETS+=("fixDRADockerArtifacts")

# Download the components from the MANIFEST_URL and then package those downloaded into the $AGENT_DROP_PATH
mage "${MAGE_TARGETS[@]}"

echo  "+++ Generate dependencies report"
BEAT_VERSION_FULL=$(curl -s -XGET "${MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
