#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/retry.sh
source .buildkite/scripts/steps/ess_oblt-cli.sh
source .buildkite/scripts/steps/fleet.sh

# Make sure that all tools are installed
retry 3 asdf install

GROUP_NAME=$1
TEST_SUDO=$2

if [ -z "$GROUP_NAME" ]; then
  echo "Error: Specify the group name: integration_tests_oblt-cli.sh [group_name]" >&2
  exit 1
fi

if [ -z "$TEST_SUDO" ]; then
  echo "Error: Specify the test sudo: integration_tests_oblt-cli.sh [group_name] [test_sudo]" >&2
  exit 1
fi

# Override the stack version from `.package-version` contents
# There is a time when the current snapshot is not available on cloud yet, so we cannot use the latest version automatically
# This file is managed by an automation (mage integration:UpdateAgentPackageVersion) that check if the snapshot is ready.
STACK_VERSION="$(jq -r '.stack_version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id // ""' .package-version)"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi
export METADATA_PREFIX

# Automatic retries reuse the deployment created by the original attempt.
# Manual retries continue to get a fresh stack.
if [[ "${BUILDKITE_RETRY_COUNT:-0}" -gt 0 && "${BUILDKITE_RETRY_TYPE:-}" == "automatic" ]]; then
  echo "~~~ Automatic retry: reusing the existing ESS stack"
elif [[ "${BUILDKITE_RETRY_COUNT:-0}" -gt 0 || "${FORCE_ESS_CREATE:-false}" == "true" ]]; then
  echo "~~~ The step is retried, starting the ESS stack again"
  trap 'ess_down' EXIT
  ess_up "$STACK_VERSION" "$STACK_BUILD_ID"
fi

ess_load_secrets

# Run integration tests
echo "~~~ Running integration tests"

if [[ "${GROUP_NAME}" == "kubernetes" ]]; then
  source .buildkite/scripts/install-kubectl.sh
  .buildkite/scripts/buildkite-k8s-integration-tests.sh "$@"
else
  # test binaries are needed only when running integration tests outside of k8s
  echo "~~~ Building test binaries"
  mage build:integrationTestBinaries

  # When AGENT_ARTIFACT_STEP is set the step does not depend on the packaging
  # step in the pipeline; instead the setup above runs while packaging is still
  # in progress and we only wait for the artifacts right before the tests.
  if [[ -n "${AGENT_ARTIFACT_STEP:-}" ]]; then
    .buildkite/scripts/steps/wait-for-step.sh "${AGENT_ARTIFACT_STEP}"
    echo "~~~ Downloading agent packages from step ${AGENT_ARTIFACT_STEP}"
    for glob in ${AGENT_ARTIFACT_GLOBS:?"AGENT_ARTIFACT_GLOBS must be set together with AGENT_ARTIFACT_STEP"}; do
      buildkite-agent artifact download "${glob}" . --step "${AGENT_ARTIFACT_STEP}"
    done
  fi

  if [ "$TEST_SUDO" == "true" ]; then
    sudo -E .buildkite/scripts/buildkite-integration-tests.sh "$@"
  else
    .buildkite/scripts/buildkite-integration-tests.sh "$@"
  fi
fi
