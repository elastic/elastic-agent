#!/usr/bin/env bash
set -euxo pipefail

make mage
TEST_COVERAGE=true mage unitTest