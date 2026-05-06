#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess_oblt-cli.sh

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi
export METADATA_PREFIX

ess_down
