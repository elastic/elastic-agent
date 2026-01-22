#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

STACK_VERSION="$(jq -r '.stack_version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id' .package-version)"
if [[ "${FIPS:-false}" == "true" ]]; then
  # FRH testing environment does not have same stack build IDs as CFT environment so
  # we just go with the STACK_VERSION.
  STACK_BUILD_ID=""
fi
ESS_REGION="${ESS_REGION:-gcp-us-west2}"

ess_up "$STACK_VERSION" "$STACK_BUILD_ID" "$ESS_REGION"

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
echo "BUILDKITE_JOB_ID: ${BUILDKITE_JOB_ID}"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi

buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}kibana.host" $KIBANA_HOST
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}kibana.pwd" $KIBANA_PASSWORD
buildkite-agent meta-data set --redacted-vars='' "${METADATA_PREFIX}integrations_server.host" $INTEGRATIONS_SERVER_HOST
