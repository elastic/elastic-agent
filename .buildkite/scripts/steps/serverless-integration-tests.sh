#!/usr/bin/env bash
# This script runs the serverless integration tests
set -eo pipefail

BUILDKITE=${BUILDKITE:-}

if [ -n "$BUILDKITE" ]; then
    buildkite-agent artifact download "build/distributions/**" . "$BUILDKITE_BUILD_ID"
fi

echo "+++ Run integration-tests"
# TBC
