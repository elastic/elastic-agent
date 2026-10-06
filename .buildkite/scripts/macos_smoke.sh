#!/usr/bin/env bash
# Runs an integration test group on an Orka macOS VM. Expects the checkout in $PWD (src/) and
# the darwin/arm64 package produced by the packaging-darwin-arm64 step.
set -euo pipefail

GROUP_NAME=$1

echo "~~~ Downloading darwin/arm64 package"
buildkite-agent artifact download "build/distributions/elastic-agent-*-darwin-aarch64*" . --step packaging-darwin-arm64

source .buildkite/scripts/macos_install_asdf.sh

export ASDF_MAGE_VERSION="${ASDF_MAGE_VERSION:-1.14.0}"
.buildkite/scripts/steps/integration_tests_oblt-cli.sh "${GROUP_NAME}" true
