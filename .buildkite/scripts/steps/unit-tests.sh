#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

<<<<<<< HEAD
echo "--- Unit tests"
RACE_DETECTOR=true TEST_COVERAGE=true mage unitTest
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage file to build directory so it can be downloaded as an artifact
mv build/TEST-go-unit.cov "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv build/TEST-go-unit.xml build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
=======
GO_MODULE_DIR="${GO_MODULE_DIR:-.}"
case "${GO_MODULE_DIR}" in
  .)             MAGE_TARGET="test:unit";     TEST_NAME="unit" ;;
  internal/edot) MAGE_TARGET="test:unitEdot"; TEST_NAME="unit_edot" ;;
  *) echo "unsupported GO_MODULE_DIR: ${GO_MODULE_DIR}"; exit 1 ;;
esac
echo "--- Unit tests (${GO_MODULE_DIR})"

RACE_DETECTOR=true TEST_COVERAGE=true mage "${MAGE_TARGET}"
TESTS_EXIT_STATUS=$?
echo "--- Prepare artifacts"
# Copy coverage files to build directory so they can be downloaded as artifacts.
mv "build/TEST-go-${TEST_NAME}.cov" "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv "build/TEST-go-${TEST_NAME}.xml" build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
>>>>>>> 410bb18 (ci: split EDOT tests into separate runners (#17299))
exit $TESTS_EXIT_STATUS
