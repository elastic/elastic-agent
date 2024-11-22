#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

STACK_PROVISIONER="${1:-"stateful"}"
MAGE_TARGET="${2:-"integration:test"}"
MAGE_SUBTARGET="${3:-""}"


# Override the stack version from `.package-version` contents
# There is a time when the current snapshot is not available on cloud yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.

STACK_VERSION="$(cat .package-version)"
if [[ -n "$STACK_VERSION" ]]; then
    STACK_VERSION=${STACK_VERSION}"-SNAPSHOT"
fi

# Run integration tests
set +e
AGENT_VERSION="8.17.0-SNAPSHOT"  AGENT_STACK_VERSION="8.17.0-SNAPSHOT" TEST_INTEG_CLEAN_ON_EXIT=true  STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage $MAGE_TARGET $MAGE_SUBTARGET
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
