#!/usr/bin/env bash
# Builds the helper binaries the integration tests need (currently only the
# fake component), without going through mage.
#
# `mage build:integrationTestBinaries` builds the same binary, but compiling the
# magefile first costs ~2.5 minutes on a fresh CI agent, while the binary itself
# builds in seconds. Keep the list of packages in sync with
# getIntegrationTestBinariesPath in magefile.go.
#
# The output path mirrors buildTestBinaries in magefile.go: the binary is placed
# next to its package, named after the package directory, so that the tests find
# it (see testing/integration/ess/fakes.go).
#
# This script runs as the agent user, before the tests are started (as root for
# the sudo groups). It also downloads the modules the test binary needs, so that
# the shared module cache is populated by the agent user: a root `go test`
# downloading them would leave root-owned directories behind that break later
# Go invocations by the agent user (such as `mage integration:clean` in the
# pre-exit hook). The test run would download the same modules otherwise, so
# this costs no extra time.
set -euo pipefail

# shellcheck source=.buildkite/scripts/retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/retry.sh"

# Same default as .buildkite/scripts/buildkite-integration-tests.sh.
: "${TEST_PACKAGE:="github.com/elastic/elastic-agent/testing/integration"}"

download_test_modules() {
  echo "Downloading modules for ${TEST_PACKAGE}"
  go list -deps -test -tags integration "${TEST_PACKAGE}" >/dev/null
}

build_integration_test_binary() {
  local pkg=$1
  local output
  output="${pkg}/$(basename "${pkg}")"
  if [[ "$(go env GOOS)" == "windows" ]]; then
    output="${output}.exe"
  fi
  echo "Building ${output}"
  go build -v -o "${output}" "./${pkg}"
}

echo "~~~ Building test binaries"
retry 3 download_test_modules
retry 3 build_integration_test_binary pkg/component/fake/component
