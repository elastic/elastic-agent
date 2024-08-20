#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

GROUP_NAME=$1
if [ -z "$GROUP_NAME" ]; then
  echo "Error: Specify the group name: sudo-integration-tests.sh [group_name] [tests_to_run]" >&2
  exit 1
fi
TESTS_TO_RUN=$2
if [ -z "$TESTS_TO_RUN" ]; then
  echo "Error: Specify the tests to run: sudo-integration-tests.sh [group_name] [tests_to_run]" >&2
  exit 1
fi

# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
OVERRIDE_AGENT_PACKAGE_VERSION="$(cat .package-version)"
OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"

# echo "~~~ Building test binaries"
# mage build:testBinaries

# ess_up $OVERRIDE_TEST_AGENT_VERSION || echo "Failed to start ESS stack" >&2
# trap 'ess_down' EXIT

# Run integration tests
echo "~~~ Running integration tests"
sudo -E .buildkite/scripts/sudo-integration-tests.sh $@
