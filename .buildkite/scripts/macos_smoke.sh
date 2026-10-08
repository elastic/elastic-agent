#!/usr/bin/env bash
# Runs an integration test group on an Orka macOS VM. Expects the checkout in $PWD (src/) and
# the darwin/arm64 package produced by the packaging-darwin-arm64 step.
set -euo pipefail

GROUP_NAME=$1

echo "~~~ Downloading darwin/arm64 package"
buildkite-agent artifact download "build/distributions/elastic-agent-*-darwin-aarch64*" . --step packaging-darwin-arm64

source .buildkite/scripts/macos_install_asdf.sh

# Failing tests keep their temp dirs (artifact extractions, hundreds of MB each) and the Orka VM only has
# ~30 GB free: drop the old ones while the tests run. Diagnostics zips go to build/diagnostics, not /tmp.
(
  while true; do
    sleep 120
    sudo find /private/tmp -maxdepth 1 -name 'Test*' -mmin +20 -exec rm -rf {} + 2>/dev/null || true
  done
) &
JANITOR_PID=$!
trap 'kill "${JANITOR_PID}" 2>/dev/null || true' EXIT

export ASDF_MAGE_VERSION="${ASDF_MAGE_VERSION:-1.14.0}"
.buildkite/scripts/steps/integration_tests_oblt-cli.sh "${GROUP_NAME}" true
