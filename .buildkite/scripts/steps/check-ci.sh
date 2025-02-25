#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh

set +e
set +x
echo "--- Check grep"
grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\-[a-zA-Z]+[0-9]+)?' "version/version.go"
set -e
set -x

echo "--- Check CI"
go version
mage --version
BEAT_VERSION=$(make get-version)
echo "Beat version: $BEAT_VERSION"
make check-ci