#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh

echo "+++ Build Agent artifacts"
SNAPSHOT=""
VERSION_QUALIFIER="${VERSION_QUALIFIER:=""}"
BEAT_VERSION_FULL=$BEAT_VERSION

if [ "$DRA_WORKFLOW" == "snapshot" ]; then
    SNAPSHOT="true"
    BEAT_VERSION_FULL="${BEAT_VERSION}-SNAPSHOT"
fi

if [[ "$DRA_WORKFLOW" == "staging" ]] && [[ -n "$VERSION_QUALIFIER" ]]; then
    BEAT_VERSION_FULL="${BEAT_VERSION_FULL}-${VERSION_QUALIFIER}"
fi

# USE_PACKAGE_VERSION=false: binary-DRA stamps version.go's version, not .package-version's.
SNAPSHOT=$SNAPSHOT WINDOWS_NPCAP="true" USE_PACKAGE_VERSION=false mage packageAgentCore
chmod -R 777 build/distributions

echo "+++ Generate dependencies report"
./dev-tools/dependencies-report
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
