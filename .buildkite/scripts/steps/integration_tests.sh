#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

STACK_PROVISIONER="${1:-"stateful"}"
MAGE_TARGET="${2:-"integration:test"}"
MAGE_SUBTARGET="${3:-""}"


# Override the agent stack version using a string with format <major>.<minor>.<patch>
# NOTE: use only after version bump when the new snapshot is not yet available, for example:
# OVERRIDE_AGENT_PACKAGE_VERSION="8.10.3" otherwise OVERRIDE_AGENT_PACKAGE_VERSION="".
OVERRIDE_AGENT_STACK_VERSION="8.12.0"

if [[ -n "$OVERRIDE_AGENT_STACK_VERSION" ]]; then
  OVERRIDE_AGENT_STACK_VERSION=${OVERRIDE_AGENT_STACK_VERSION}"-SNAPSHOT"
else
 OVERRIDE_AGENT_STACK_VERSION=""
fi
# PACKAGE
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package

# Run integration tests
set +e
AGENT_STACK_VERSION="${OVERRIDE_AGENT_STACK_VERSION}" TEST_INTEG_CLEAN_ON_EXIT=true  STACK_PROVISIONER="$STACK_PROVISIONER" SNAPSHOT=true mage "$MAGE_TARGET" "$MAGE_SUBTARGET"
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
