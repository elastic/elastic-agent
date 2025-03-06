#!/usr/bin/env bash
# This script runs the helm-charts for the given environment
# STAGING OR SNAPSHOT

# shellcheck disable=SC1091
source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- mage package tests"
SNAPSHOT=true mage helm:package
