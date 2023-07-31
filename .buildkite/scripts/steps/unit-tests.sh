#!/usr/bin/env bash
set -euxo pipefail

source .buildkite/scripts/bootstrap.sh

TEST_COVERAGE=true mage unitTest