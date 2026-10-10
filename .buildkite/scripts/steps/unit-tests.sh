#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

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
# Copy coverage file to build directory so it can be downloaded as an artifact
mv "build/TEST-go-${TEST_NAME}.cov" "coverage-${BUILDKITE_JOB_ID:go-unit}.out"
mv "build/TEST-go-${TEST_NAME}.xml" build/"TEST-${BUILDKITE_JOB_ID:go-unit}.xml"
exit $TESTS_EXIT_STATUS
