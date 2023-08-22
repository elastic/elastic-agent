#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

echo "--- Unit tests"
TEST_COVERAGE=true mage unitTest