#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

# Override the agent package version using a string with format <major>.<minor>.<patch>
# NOTE: use only after version bump when the new version is not yet available
PINNED_AGENT_PACKAGE_VERSION="8.10.2"

if [[ -n "$PINNED_AGENT_PACKAGE_VERSION" ]]; then
PINNED_AGENT_VERSION=${PINNED_AGENT_PACKAGE_VERSION}"-SNAPSHOT"
fi
# PACKAGE
AGENT_PACKAGE_VERSION="${PINNED_AGENT_PACKAGE_VERSION}" DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage package

# Run integration tests
set +e
# Use 8.10.2-SNAPSHOT until the first 8.10.3-SNAPSHOT is produced.
AGENT_VERSION="${PINNED_AGENT_VERSION}" TEST_INTEG_AUTH_ESS_REGION=azure-eastus2 TEST_INTEG_CLEAN_ON_EXIT=true SNAPSHOT=true mage integration:test
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
