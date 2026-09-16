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

function set_buildkite_metadata() {
  local key="$1"
  local value="$2"
  local max_attempts=3
  local delay=5

  if [[ -z "$value" ]]; then
    echo "ERROR: value for '$key' is empty — ESS provisioning may have failed" >&2
    return 1
  fi

  local attempt
  for attempt in $(seq 1 "$max_attempts"); do
    if buildkite-agent meta-data set --redacted-vars='' "$key" "$value"; then
      local stored
      stored=$(buildkite-agent meta-data get "$key" 2>/dev/null) && [[ -n "$stored" ]] && return 0
    fi
    if [[ $attempt -lt $max_attempts ]]; then
      echo "Attempt $attempt/$max_attempts failed for '$key', retrying in ${delay}s..." >&2
      sleep "$delay"
    fi
  done

  echo "ERROR: failed to set/verify metadata key '$key' after $max_attempts attempts" >&2
  return 1
}

echo "~~~ Publishing and verifying ESS stack metadata"
for i in "${!metadata_keys[@]}"; do
  set_buildkite_metadata "${metadata_keys[$i]}" "${metadata_values[$i]}"
  echo "✓ ${metadata_keys[$i]}"
done
