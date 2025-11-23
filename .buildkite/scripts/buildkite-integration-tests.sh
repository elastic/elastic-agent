#!/usr/bin/env bash


GROUP_NAME=$1
TEST_SUDO=$2

# Set default TEST_PACKAGE if not already defined in env or argument
: "${TEST_PACKAGE:="github.com/elastic/elastic-agent/testing/integration"}"

if [ -z "$GROUP_NAME" ]; then
  echo "Error: Specify the group name: sudo-integration-tests.sh [group_name]" >&2
  exit 1
fi

if [ -z "$TEST_SUDO" ]; then
  echo "Error: Specify the test sudo: sudo-integration-tests.sh [group_name] [test_sudo]" >&2
  exit 1
fi

if [ "${FIPS:-false}" == "true" ]; then
  echo "~~~FIPS: Checking msft-go is installed"
  GOEXPERIMENT=systemcrypto go version
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

make install-gotestsum

if [[ -z "${AGENT_VERSION:-}" ]]; then
  if [[ -f "${WORKSPACE}/.package-version" ]]; then
    AGENT_VERSION="$(jq -r '.version' .package-version)"
    echo "~~~ Agent version: ${AGENT_VERSION} (from .package-version)"
  else
    AGENT_VERSION=$(grep "const defaultBeatVersion =" version/version.go | cut -d\" -f2)
    AGENT_VERSION="${AGENT_VERSION}-SNAPSHOT"
    echo "~~~ Agent version: ${AGENT_VERSION} (from version/version.go)"
  fi

  export AGENT_VERSION
else
  echo "~~~ Agent version: ${AGENT_VERSION} (specified by env var)"
fi

os_data=$(uname -spr | tr ' ' '_')
root_suffix=""
if [ "$TEST_SUDO" == "true" ]; then
  root_suffix="_sudo"
fi
fully_qualified_group_name="${GROUP_NAME}${root_suffix}_${os_data}"
outputXML="build/${fully_qualified_group_name}.integration.xml"
outputJSON="build/${fully_qualified_group_name}.integration.out.json"

echo "~~~ Integration tests: ${GROUP_NAME}"
# -test.timeout=2h0m0s is set because some tests normally take up to 45 minutes.
# This 2-hour timeout provides enough room for future, potentially longer tests,
# while still enforcing a reasonable upper limit on total execution time.
# See: https://pkg.go.dev/cmd/go#hdr-Testing_flags

GOTEST_OPTS="-test.shuffle on -test.timeout 2h0m0s"
if [[ "${BUILDKITE_PULL_REQUEST:="false"}" != "false" ]]; then
  GOTEST_OPTS="${GOTEST_OPTS} -test.short"
fi
GOTEST_ARGS=(-tags integration ${GOTEST_OPTS} "${TEST_PACKAGE}" -v -args "-integration.groups=${GROUP_NAME}" "-integration.sudo=${TEST_SUDO}" "-integration.fips=${FIPS:-false}")
set +e
TEST_BINARY_NAME="elastic-agent" AGENT_VERSION="${AGENT_VERSION}" SNAPSHOT=true \
  gotestsum --no-color -f standard-quiet --junitfile-hide-skipped-tests --junitfile "${outputXML}" --jsonfile "${outputJSON}" -- "${GOTEST_ARGS[@]}"
TESTS_EXIT_STATUS=$?
set -e

if [[ $TESTS_EXIT_STATUS -ne 0 ]]; then
   echo "^^^ +++"
   echo "Integration tests failed"
fi

if [ -f "$outputXML" ]; then
  go install github.com/kitproj/junit2html@latest
  junit2html < "$outputXML" > build/TEST-report.html
else
    echo "Cannot generate HTML test report: $outputXML not found"
fi

exit $TESTS_EXIT_STATUS
