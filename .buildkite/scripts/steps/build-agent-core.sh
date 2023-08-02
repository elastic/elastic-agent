#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh
BEAT_VERSION=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' "${WORKSPACE}/version/version.go")
export DRA_VERSION="${BEAT_VERSION}"

echo "+++ Build Agent artifacts"
SNAPSHOT=""
BEAT_VERSION_FULL=$BEAT_VERSION
if [ "$DRA_WORKFLOW" == "snapshot" ]; then
    SNAPSHOT="true"
    BEAT_VERSION_FULL="${BEAT_VERSION}-SNAPSHOT"
fi

SNAPSHOT=$SNAPSHOT mage packageAgentCore
chmod -R 777 build/distributions

echo  "+++ Generate dependencies report"
./dev-tools/dependencies-report
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
