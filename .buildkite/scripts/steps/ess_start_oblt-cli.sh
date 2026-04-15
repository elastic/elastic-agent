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

preinstall_fleet_packages
