#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

# Make sure that all tools are installed
asdf install

GROUP_NAME=$1
TEST_SUDO=$2

if [ -z "$GROUP_NAME" ]; then
  echo "Error: Specify the group name: integration_tests_tf.sh [group_name]" >&2
  exit 1
fi

if [ -z "$TEST_SUDO" ]; then
  echo "Error: Specify the test sudo: integration_tests_tf.sh [group_name] [test_sudo]" >&2
  exit 1
fi

ESS_REGION=${ESS_REGION:-""}

# Override the stack version from `.package-version` contents
# There is a time when the current snapshot is not available on cloud yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
STACK_VERSION="$(jq -r '.stack_version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id' .package-version)"
if [[ "${FIPS:-false}" == "true" ]]; then
  # FRH testing environment does not have same stack build IDs as CFT environment so
  # we just go with the STACK_VERSION.
  STACK_BUILD_ID=""
fi

# If the step is retried, we start the stack again.
# BUILDKITE_RETRY_COUNT == "0" for the first run
# BUILDKITE_RETRY_COUNT > 0 for the retries
if [[ "${BUILDKITE_RETRY_COUNT}" -gt 0 || "${FORCE_ESS_CREATE:-false}" == "true" ]]; then
  echo "~~~ The steps is retried, starting the ESS stack again"
  trap 'ess_down "$ESS_REGION"' EXIT
  ess_up "$STACK_VERSION" "$STACK_BUILD_ID" "$ESS_REGION"
else
  # For the first run, we start the stack in the start_ess.sh step and it sets the meta-data
  echo "~~~ Receiving ESS stack metadata"
  METADATA_PREFIX=""
  if [[ "${FIPS:-false}" == "true" ]]; then
    METADATA_PREFIX="fips."
    echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
  fi
  export ELASTICSEARCH_HOST=$(buildkite-agent meta-data get "${METADATA_PREFIX}es.host")
  export ELASTICSEARCH_USERNAME=$(buildkite-agent meta-data get "${METADATA_PREFIX}es.username")
  export ELASTICSEARCH_PASSWORD=$(buildkite-agent meta-data get "${METADATA_PREFIX}es.pwd")
  export KIBANA_HOST=$(buildkite-agent meta-data get "${METADATA_PREFIX}kibana.host")
  export KIBANA_USERNAME=$(buildkite-agent meta-data get "${METADATA_PREFIX}kibana.username")
  export KIBANA_PASSWORD=$(buildkite-agent meta-data get "${METADATA_PREFIX}kibana.pwd")
  export INTEGRATIONS_SERVER_HOST=$(buildkite-agent meta-data get "${METADATA_PREFIX}integrations_server.host")
  echo "Elasticsearch Host: ${ELASTICSEARCH_HOST}"
fi

# Run integration tests
echo "~~~ Running integration tests"

if [[ "${GROUP_NAME}" == "kubernetes" ]]; then
  source .buildkite/scripts/install-kubectl.sh
  .buildkite/scripts/buildkite-k8s-integration-tests.sh $@
else
  # test binaries are needed only when running integration tests outside of k8s
  echo "~~~ Building test binaries"
  mage build:testBinaries

  if [ "$TEST_SUDO" == "true" ]; then
    sudo -E .buildkite/scripts/buildkite-integration-tests.sh $@
  else
    .buildkite/scripts/buildkite-integration-tests.sh $@
  fi
fi

