#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/bootstrap.sh

echo "+++ Build Agent artifacts"
SNAPSHOT=""
if [ "$WORKFLOW" == "snapshot" ]; then
    SNAPSHOT="true"
fi
SNAPSHOT=$SNAPSHOT mage packageAgentCore
chmod -R 777 build/distributions
