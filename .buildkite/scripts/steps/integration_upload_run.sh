#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

mage integration:testOnRemote
