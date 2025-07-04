#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

# Make sure that all tools are installed
asdf install

# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

echo "~~~ Building test binaries"
mage build:testBinaries

# Remove deployment on exit
trap 'ess_down' EXIT

preinstall_fleet_packages

# Run integration tests
echo "~~~ Running sudo ECH integration tests"
./buildkite/scripts/buildkite-integration-tests.sh ech true
