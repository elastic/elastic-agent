#!/usr/bin/env bash
set -euo pipefail

# Set required env vars
source .buildkite/scripts/common.sh

mage package
