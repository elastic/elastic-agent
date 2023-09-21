#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

# PACKAGE
DEV=true EXTERNAL=true SNAPSHOT=true PLATFORMS=linux/amd64,linux/arm64 PACKAGES=tar.gz mage package

# Run integration tests
set +e
# Use 8.10.2-SNAPSHOT until the first 8.10.3-SNAPSHOT is produced.
AGENT_STACK_VERSION="8.10.2-SNAPSHOT" TEST_INTEG_CLEAN_ON_EXIT=true SNAPSHOT=true mage integration:test
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
