#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
mv build/TEST-edot.cov "coverage-edot-${BUILDKITE_JOB_ID}.out" 2>/dev/null || true
mv build/TEST-edot.xml build/"TEST-edot-${BUILDKITE_JOB_ID}.xml" 2>/dev/null || true
exit $TESTS_EXIT_STATUS
