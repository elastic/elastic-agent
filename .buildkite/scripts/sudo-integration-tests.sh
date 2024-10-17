#!/usr/bin/env bash

# The script is used to run integration tests with sudo
source /opt/buildkite-agent/hooks/pre-command 
source .buildkite/hooks/pre-command || echo "No pre-command hook found"

GROUP_NAME=$1
# TESTS_TO_RUN=$2

echo "~~~ Running integration tests as $USER"
echo "~~~ Integration tests: ${GROUP_NAME}"
gotestsum --version
PACKAGE_VERSION="$(cat .package-version)"
if [[ -n "$PACKAGE_VERSION" ]]; then
    PACKAGE_VERSION=${PACKAGE_VERSION}"-SNAPSHOT"
fi
set +e
-integration.groups="default"
AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true go test -tags integration github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}"
# AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true TEST_DEFINE_PREFIX="sudo_${GROUP_NAME}_ubuntu" gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags integration -test.shuffle on -test.timeout 2h0m0s -test.run "${TESTS_TO_RUN}" github.com/elastic/elastic-agent/testing/integration
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
