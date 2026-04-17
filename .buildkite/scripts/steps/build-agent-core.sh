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

# Binary-DRA must stamp version.go's version (and the commit hash passed in
# via BEAT_VERSION/DRA_WORKFLOW), not whatever .package-version points at.
# The default USE_PACKAGE_VERSION=true added for local-dev ergonomics would
# otherwise override BeatVersion and force Snapshot=true, breaking staging
# DRA builds. Disable it explicitly.
SNAPSHOT=$SNAPSHOT WINDOWS_NPCAP="true" USE_PACKAGE_VERSION=false mage packageAgentCore
chmod -R 777 build/distributions

echo  "+++ Generate dependencies report"
./dev-tools/dependencies-report
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION_FULL}.csv"
