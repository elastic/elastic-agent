#!/usr/bin/env bash

set -euo pipefail

.buildkite/scripts/bootstrap.sh

echo "+++ Build Agent artifacts"
mage packageAgentCore
chmod -R 777 build/distributions
