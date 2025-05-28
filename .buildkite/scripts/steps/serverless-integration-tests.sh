#!/usr/bin/env bash
# This script runs the serverless integration tests
set -eo pipefail

BUILDKITE=${BUILDKITE:-}

# Check if the required binary is installed
if ! command -v oblt-cli &> /dev/null; then
    echo "oblt-cli is not installed. Please install it to run this script."
    exit 1
fi

if [ -n "$BUILDKITE" ]; then
    buildkite-agent artifact download "build/distributions/**" . "$BUILDKITE_BUILD_ID"
fi

if [ -z "$BUILDKITE" ]; then
    echo "~~~ Creating the cluster if no CI environment is detected"
    # TODO name of the cluster should be set dynamically to avoid conflicts when local testing.
    cluster_name=$(.buildkite/scripts/steps/provision-cluster.sh "ea-int-test-local")
else
    # Use the day of the week to get a unique cluster name for each day
    # The provision happens somewhere else.
    cluster_name="ea-int-test-$(date +%a | tr '[:upper:]' '[:lower:]')"
fi

echo "~~~ Retrieving the credentials for the cluster"
oblt-cli cluster secrets env --cluster-name="${cluster_name}" --output-file="${PWD}/env.sh"

source "${PWD}/env.sh" && rm -f "${PWD}/env.sh"

echo "+++ Run integration-tests"
# TBC
