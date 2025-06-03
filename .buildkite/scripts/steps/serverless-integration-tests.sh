#!/usr/bin/env bash
# This script runs the serverless integration tests
set -eo pipefail

source .buildkite/scripts/common2.sh

# Make sure that all tools are installed
asdf install

echo "~~~ Building test binaries"
mage build:testBinaries

# TODO: move to common.sh when it's refactored
# BK analytics
echo "--- Prepare BK test analytics token :vault:"
BUILDKITE_ANALYTICS_TOKEN=$(vault kv get -field token kv/ci-shared/platform-ingest/buildkite_analytics_token)
export BUILDKITE_ANALYTICS_TOKEN

# Run integration tests
echo "~~~ Running serverless integration tests"
sudo -E .buildkite/scripts/buildkite-integration-tests.sh fleet true TestLogIngestionFleetManaged

