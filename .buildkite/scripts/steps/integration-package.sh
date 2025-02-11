#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

export SNAPSHOT="true"
export EXTERNAL="true"

mage package
