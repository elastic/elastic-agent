#!/usr/bin/env bash
set -uo pipefail

source .buildkite/scripts/common.sh

echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov coverage.out
mv build/TEST-go-unit.xml "TEST-${BUILDKITE_JOB_ID}.xml"
exit $TESTS_EXIT_STATUS
