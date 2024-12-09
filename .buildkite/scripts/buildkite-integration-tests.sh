#!/usr/bin/env bash

<<<<<<< HEAD
=======

>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
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
<<<<<<< HEAD
  echo "Re-initializing ASDF. The user is changed to root..."
  export HOME=/opt/buildkite-agent
  source /opt/buildkite-agent/hooks/pre-command
=======
  echo "Re-initializing ASDF. The user is changed to root..."  
  export HOME=/opt/buildkite-agent
  source /opt/buildkite-agent/hooks/pre-command 
>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
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

<<<<<<< HEAD
set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true gotestsum --no-color -f standard-quiet --junitfile "build/${GROUP_NAME}.integration.xml" --jsonfile "build/${GROUP_NAME}.integration.out.json" -- -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}" -integration.sudo="${TEST_SUDO}"
TESTS_EXIT_STATUS=$?
set -e

# HTML report
outputXML="build/${GROUP_NAME}.integration.xml"

=======
os_data=$(uname -spr | tr ' ' '_')
root_suffix=""
if [ "$TEST_SUDO" == "true" ]; then
  root_suffix="_sudo"
fi
fully_qualified_group_name="${GROUP_NAME}${root_suffix}_${os_data}"
outputXML="build/${fully_qualified_group_name}.integration.xml"
outputJSON="build/${fully_qualified_group_name}.integration.out.json"
set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${PACKAGE_VERSION}" SNAPSHOT=true gotestsum --no-color -f standard-quiet --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- -tags integration -test.shuffle on -test.timeout 2h0m0s github.com/elastic/elastic-agent/testing/integration -v -args -integration.groups="${GROUP_NAME}" -integration.sudo="${TEST_SUDO}"
TESTS_EXIT_STATUS=$?
set -e

>>>>>>> 950e1d74ba (build(deps): bump github.com/elastic/elastic-agent-libs from 0.17.3 to 0.17.4 (#6237))
if [ -f "$outputXML" ]; then
  go install github.com/alexec/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
