#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

AGENT_PACKAGE_VERSION=8.16.0 SNAPSHOT=true mage integration:buildkite
echo "=== Start Generated Pipeline ==="
cat steps.yml
echo "=== End Generated Pipeline ==="

buildkite-agent pipeline upload --format yaml steps.yml
