#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

echo "--- Unit tests"
TEST_COVERAGE=true mage unitTest
# Copy coverage file to build directory so it can be downloaded as an artifact
cp build/TEST-go-unit.cov coverage.out