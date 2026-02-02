#!/usr/bin/env bash
source .buildkite/scripts/common.sh
set +euo pipefail

echo "--- Download packages from artifacts"
buildkite-agent artifact download build/distributions/elastic-agent-* .

echo "--- Test packages"
mage testPackages
