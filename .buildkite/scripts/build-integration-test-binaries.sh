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
set -euo pipefail

# shellcheck source=.buildkite/scripts/retry.sh
source "$(dirname "${BASH_SOURCE[0]}")/retry.sh"

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
retry 3 build_integration_test_binary pkg/component/fake/component
