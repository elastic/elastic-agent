#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/bootstrap.sh

echo "+++ Build Agent artifacts"
SNAPSHOT=$SNAPSHOT mage packageAgentCore
chmod -R 777 build/distributions

echo  "+++ Generate dependencies report"
./dev-tools/dependencies-report
mkdir -p build/distributions/reports
mv dependencies.csv "build/distributions/reports/dependencies-${BEAT_VERSION}.csv"

buildkite-agent artifact upload "build/**/*"
