#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/bootstrap.sh

make mage
TEST_COVERAGE=true mage unitTest