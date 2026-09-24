#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess_oblt-cli.sh
source .buildkite/scripts/steps/fleet.sh

STACK_VERSION="$(jq -r '.stack_version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id // ""' .package-version)"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi
export METADATA_PREFIX

if [[ "${BUILDKITE_RETRY_COUNT:-0}" -gt 0 && "${BUILDKITE_RETRY_TYPE:-}" == "automatic" ]]; then
  echo "~~~ Automatic retry: reusing the existing ESS stack"
  ess_load_secrets
else
  ess_up "$STACK_VERSION" "$STACK_BUILD_ID"

  # Publish the shared cluster name for the global cleanup step. Per-step
  # retries must not overwrite it, so cleanup continues to target this stack.
  CLUSTER_NAME="$(jq -r '.ClusterName' "${PWD}/cluster-info.json")"
  if [ -z "${CLUSTER_NAME}" ] || [ "${CLUSTER_NAME}" = "null" ]; then
    echo "Error: Failed to extract ClusterName from cluster-info.json" >&2
    exit 1
  fi
  buildkite-agent meta-data set "${METADATA_PREFIX}cluster-name" "${CLUSTER_NAME}"
fi

preinstall_fleet_packages
