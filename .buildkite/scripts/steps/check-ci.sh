#!/usr/bin/env bash

set -euo pipefail

echo "--- Check CI"

BEAT_VERSION=$(make get-version)
echo "Beat version: $BEAT_VERSION"
make check-ci