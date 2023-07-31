#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/common.sh

TEST_COVERAGE=true mage unitTest