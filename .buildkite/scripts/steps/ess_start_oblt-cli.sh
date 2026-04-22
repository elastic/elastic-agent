#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess_oblt-cli.sh
source .buildkite/scripts/steps/fleet.sh

STACK_VERSION="$(jq -r '.stack_version' .package-version)"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi
export METADATA_PREFIX

ess_up "$STACK_VERSION"

# Publish the shared cluster name via meta-data so the global cleanup step
# (ess_down_oblt-cli.sh) can find and destroy it. Per-step retries intentionally
# don't touch this key - they rely on their own local cluster-info.json for
# teardown - so this always points at the shared cluster created above.
CLUSTER_NAME="$(jq -r '.ClusterName' "${PWD}/cluster-info.json")"
if [ -z "${CLUSTER_NAME}" ] || [ "${CLUSTER_NAME}" = "null" ]; then
  echo "Error: Failed to extract ClusterName from cluster-info.json" >&2
  exit 1
fi
buildkite-agent meta-data set "${METADATA_PREFIX}cluster-name" "${CLUSTER_NAME}"

preinstall_fleet_packages
