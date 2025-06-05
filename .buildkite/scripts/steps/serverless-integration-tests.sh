#!/usr/bin/env bash
# This script runs the serverless integration tests
set -eo pipefail

source .buildkite/scripts/common2.sh

# Make sure that all tools are installed
asdf install

echo "~~~ Building test binaries"
mage build:testBinaries

# Run integration tests
echo "~~~ Running serverless integration tests"
sudo -E .buildkite/scripts/buildkite-integration-tests.sh fleet true TestLogIngestionFleetManaged

