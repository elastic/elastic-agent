#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

ess_up $OVERRIDE_STACK_VERSION

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
echo "BUILDKITE_JOB_ID: ${BUILDKITE_JOB_ID}"

METADATA_PREFIX=""
if [[ "${FIPS:-false}" == "true" ]]; then
  METADATA_PREFIX="fips."
  echo "Using FIPS metadata prefix: ${METADATA_PREFIX}"
fi

buildkite-agent meta-data set "${METADATA_PREFIX}es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "${METADATA_PREFIX}es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "${METADATA_PREFIX}es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "${METADATA_PREFIX}kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "${METADATA_PREFIX}kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "${METADATA_PREFIX}kibana.pwd" $KIBANA_PASSWORD
buildkite-agent meta-data set "${METADATA_PREFIX}integrations_server.host" $INTEGRATIONS_SERVER_HOST
