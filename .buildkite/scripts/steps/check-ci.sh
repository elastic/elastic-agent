#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh

echo "--- Check CI"
go version
mage --version
BEAT_VERSION=$(make get-version)
echo "Beat version: $BEAT_VERSION"

asdf current
asdf reshim golang
make check-ci
