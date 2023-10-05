#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

# Override the agent package version using a string with format <major>.<minor>.<patch>
# NOTE: use only after version bump when the new version is not yet available, for example:
# OVERRIDE_AGENT_PACKAGE_VERSION="8.10.3"
OVERRIDE_AGENT_PACKAGE_VERSION="8.10.2"

if [[ -n "$OVERRIDE_AGENT_PACKAGE_VERSION" ]]; then
  OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"
else
 OVERRIDE_TEST_AGENT_VERSION=""
fi
# PACKAGE
AGENT_PACKAGE_VERSION="${OVERRIDE_AGENT_PACKAGE_VERSION}" DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64,windows/amd64 PACKAGES=tar.gz,zip mage package

# Run integration tests
set +e
AGENT_VERSION="${OVERRIDE_TEST_AGENT_VERSION}" TEST_INTEG_CLEAN_ON_EXIT=true SNAPSHOT=true mage integration:test
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
