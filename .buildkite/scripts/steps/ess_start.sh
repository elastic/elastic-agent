#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

STACK_VERSION="$(jq -r '.stack_version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id // ""' .package-version)"
# if [[ "${FIPS:-false}" == "true" ]]; then
#   # FRH testing environment does not have same stack build IDs as CFT environment so
#   # we just go with the STACK_VERSION.
#   STACK_BUILD_ID=""
# fi
ESS_REGION="${ESS_REGION:-gcp-us-west2}"

ess_up "$STACK_VERSION" "$STACK_BUILD_ID" "$ESS_REGION"

wait_for_stack

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
echo "BUILDKITE_JOB_ID: ${BUILDKITE_JOB_ID}"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi

metadata_keys=(
  "${METADATA_PREFIX}es.host"
  "${METADATA_PREFIX}es.username"
  "${METADATA_PREFIX}es.pwd"
  "${METADATA_PREFIX}kibana.host"
  "${METADATA_PREFIX}kibana.username"
  "${METADATA_PREFIX}kibana.pwd"
  "${METADATA_PREFIX}integrations_server.host"
)
metadata_values=(
  "$ELASTICSEARCH_HOST"
  "$ELASTICSEARCH_USERNAME"
  "$ELASTICSEARCH_PASSWORD"
  "$KIBANA_HOST"
  "$KIBANA_USERNAME"
  "$KIBANA_PASSWORD"
  "$ELASTIC_APM_SERVER_URL"
)

echo "~~~ Publishing and verifying ESS stack metadata"
for i in "${!metadata_keys[@]}"; do
  key="${metadata_keys[$i]}"
  value="${metadata_values[$i]}"
  buildkite-agent meta-data set --redacted-vars='' "$key" "$value"
  stored=$(buildkite-agent meta-data get "$key") || {
    echo "ERROR: failed to read back metadata key '$key' after setting it" >&2
    exit 1
  }
  if [[ -z "$stored" ]]; then
    echo "ERROR: metadata key '$key' was set but reads back as empty" >&2
    exit 1
  fi
  echo "✓ $key"
done
