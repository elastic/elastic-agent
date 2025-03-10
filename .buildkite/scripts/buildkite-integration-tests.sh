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

go install gotest.tools/gotestsum
gotestsum --version

# Parsing version.go. Will be simplified here: https://github.com/elastic/ingest-dev/issues/4925
AGENT_VERSION=$(grep "const defaultBeatVersion =" version/version.go | cut -d\" -f2)
AGENT_VERSION="${AGENT_VERSION}-SNAPSHOT"
export AGENT_VERSION
echo "~~~ Agent version: ${AGENT_VERSION}"

os_data=$(uname -spr | tr ' ' '_')
root_suffix=""
if [ "$TEST_SUDO" == "true" ]; then
  root_suffix="_sudo"
fi
fully_qualified_group_name="${GROUP_NAME}${root_suffix}_${os_data}"
outputXML="build/${fully_qualified_group_name}.integration.xml"
outputJSON="build/${fully_qualified_group_name}.integration.out.json"

echo "~~~ Integration tests: ${GROUP_NAME}"

set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${AGENT_VERSION}" SNAPSHOT=true gotestsum --no-color -f standard-quiet --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}" -integration.sudo="${TEST_SUDO}"
TESTS_EXIT_STATUS=$?
set -e

if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
