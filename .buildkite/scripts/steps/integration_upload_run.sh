#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

echo "~~~ Downloading packaging artifacts"
buildkite-agent artifact download build/distributions/** . --step 'package-it'

# Override the agent package version using a string with format <major>.<minor>.<patch>
# There is a time when the snapshot is not built yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

if [[ "${TEST_REQUIRES_STACK}" -gt 0 ]]; then
  # If the step is retried, we start the stack again.
  # BUILDKITE_RETRY_COUNT == "0" for the first run
  # BUILDKITE_RETRY_COUNT > 0 for the retries
  if [[ "${BUILDKITE_RETRY_COUNT}" -gt 0 ]]; then
    echo "~~~ The steps is retried, starting the ESS stack again"
    ess_up $OVERRIDE_STACK_VERSION || echo "Failed to start ESS stack" >&2
    trap 'ess_down' EXIT
  else
    # For the first run, we start the stack in the start_ess.sh step and it sets the meta-data
    echo "~~~ Receiving ESS stack metadata"
    export ELASTICSEARCH_HOST=$(buildkite-agent meta-data get "es.host")
    export ELASTICSEARCH_USERNAME=$(buildkite-agent meta-data get "es.username")
    export ELASTICSEARCH_PASSWORD=$(buildkite-agent meta-data get "es.pwd")
    export KIBANA_HOST=$(buildkite-agent meta-data get "kibana.host")
    export KIBANA_USERNAME=$(buildkite-agent meta-data get "kibana.username")
    export KIBANA_PASSWORD=$(buildkite-agent meta-data get "kibana.pwd")
  fi
fi

# Run integration tests
echo "~~~ Running integration tests"
if [[ "${TEST_REQUIRES_SUDO}" -gt 0 ]]; then
  sudo -E mage integration:testOnRemote
else
  mage integration:testOnRemote
fi
