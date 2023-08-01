#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

echo "--- unit tests"
TEST_COVERAGE=true mage unitTest