#!/usr/bin/env bash
source .buildkite/scripts/common.sh

# Read GOPROXY from buildkite-agent env and export if present
GOPROXY_VALUE="$(buildkite-agent env get GOPROXY)"
if [[ -n "$GOPROXY_VALUE" ]]; then
	export GOPROXY="$GOPROXY_VALUE"
fi
set +euo pipefail

echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
exit $TESTS_EXIT_STATUS
