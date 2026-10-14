#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

echo "--- Unit tests"
# test:all runs the unit tests of the root module (build/TEST-go-unit.*) and of
# the internal/edot module (build/TEST-go-unit_edot.*).
RACE_DETECTOR=true TEST_COVERAGE=true mage test:all
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage files to build directory so they can be downloaded as artifacts.
# Each module's results get a unique name so they do not collide across jobs.
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
mv build/TEST-go-unit_edot.cov "coverage-${BUILDKITE_JOB_ID:go-unit}-edot.out"
mv build/TEST-go-unit_edot.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}-edot.xml"
exit $TESTS_EXIT_STATUS
