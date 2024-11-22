#!/usr/bin/env bash

# The script is used to run integration tests with sudo
source /opt/buildkite-agent/hooks/pre-command
source .buildkite/hooks/pre-command || echo "No pre-command hook found"

# Make sure that all tools are installed
asdf install

GROUP_NAME=$1

echo "~~~ Running integration tests as $USER"
echo "~~~ Integration tests: ${GROUP_NAME}"
go install gotest.tools/gotestsum
gotestsum --version
PACKAGE_VERSION="$(cat .package-version)"
if [[ -n "$PACKAGE_VERSION" ]]; then
    PACKAGE_VERSION=${PACKAGE_VERSION}"-SNAPSHOT"
fi
set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}" -integration.sudo=true
TESTS_EXIT_STATUS=$?
set -e

# HTML report
outputXML="build/${GROUP_NAME}.integration.xml"

if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
