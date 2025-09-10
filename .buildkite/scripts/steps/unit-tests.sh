#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

echo "--- Install dependencies"
# See https://github.com/tailscale/go-cache-plugin
make install-go-cache-plugin
export GOCACHEPROG="go-cache-plugin --cache-dir=/tmp/gocache --bucket=elastic-agent-ci-go-cache"
export GOEXPERIMENT=cacheprog

echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
exit $TESTS_EXIT_STATUS
