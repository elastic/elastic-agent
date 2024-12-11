#!/usr/bin/env bash

GROUP_NAME=$1
TEST_SUDO=$2

if [ -z "$GROUP_NAME" ]; then
  echo "Error: Specify the group name: sudo-integration-tests.sh [group_name]" >&2
  exit 1
fi

if [ -z "$TEST_SUDO" ]; then
  echo "Error: Specify the test sudo: sudo-integration-tests.sh [group_name] [test_sudo]" >&2
  exit 1
fi

if [ "$TEST_SUDO" == "true" ]; then
  echo "Re-initializing ASDF. The user is changed to root..."
  export ASDF_DATA_DIR="/opt/buildkite-agent/.asdf"
  export PATH="$ASDF_DATA_DIR/bin:$ASDF_DATA_DIR/shims:$PATH"
  source /opt/buildkite-agent/hooks/pre-command
  source .buildkite/hooks/pre-command || echo "No pre-command hook found"
fi

# Make sure that all tools are installed
asdf install

echo "~~~ Running integration tests as $USER"
echo "~~~ Integration tests: ${GROUP_NAME}"

go install gotest.tools/gotestsum
gotestsum --version

PACKAGE_VERSION="$(cat .package-version)"
if [[ -n "$PACKAGE_VERSION" ]]; then
    PACKAGE_VERSION=${PACKAGE_VERSION}"-SNAPSHOT"
fi

set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}" -integration.sudo="${TEST_SUDO}"
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
