#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

target=${1:-"unitTest"}
echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage $target
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
exit $TESTS_EXIT_STATUS
