#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

STACK_PROVISIONER="${1:-"stateful"}"
MAGE_TARGET="${2:-"integration:test"}"
MAGE_SUBTARGET="${3:-""}"
USE_PACKAGE_VERSION="true"

# Run integration tests
set +e
AGENT_STACK_VERSION="${STACK_VERSION}" TEST_INTEG_CLEAN_ON_EXIT=true  STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage $MAGE_TARGET $MAGE_SUBTARGET
TESTS_EXIT_STATUS=$?
set -e

# HTML report
outputXML="build/TEST-go-integration.xml"

if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
