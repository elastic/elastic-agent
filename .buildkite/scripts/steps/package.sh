#!/bin/bash

set -euo pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

if test -z "${MANIFEST_URL=:""}"; then
  echo "Missing variable MANIFEST_URL, export it before use."
  exit 2
fi

export AGENT_DROP_PATH=build/elastic-agent-drop
mkdir -p $AGENT_DROP_PATH

# Download the components from the MANIFEST_URL and then package those downloaded into the $AGENT_DROP_PATH
mage clean downloadManifest packageUsingDRA
if [ "$FIPS" != "true" ]; then
mage ironbank
fi
mage fixDRADockerArtifacts


echo  "+++ Generate dependencies report"
BEAT_VERSION_FULL=$(curl -s -XGET "${MANIFEST_URL}" |jq '.version' -r )
bash "${_SELF}/../../../dev-tools/dependencies-report"
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
