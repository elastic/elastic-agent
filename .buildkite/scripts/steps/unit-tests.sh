#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

# function resources() {
#     while [ true ]; do
#         echo "--- System resources"
#         uname -a
#         top -l 1 | head -10
#         df -h
#         sleep 10
#     done
# }
# resources &
echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true GOMEMLIMIT=4200MiB mage unitTest
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
exit $TESTS_EXIT_STATUS
