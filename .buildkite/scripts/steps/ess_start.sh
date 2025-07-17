#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

ess_up $OVERRIDE_STACK_VERSION

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"

if [[ $BUILDKITE_STEP_KEY == "integration-fips-ess" ]]; then
    buildkite-agent meta-data set "ess.job.fips" ${BUILDKITE_JOB_ID}
else
    buildkite-agent meta-data set "ess.job" ${BUILDKITE_JOB_ID}
fi

buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "kibana.host" $KIBANA_HOST --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD --job ${BUILDKITE_JOB_ID}
buildkite-agent meta-data set "integrations_server.host" $INTEGRATIONS_SERVER_HOST --job ${BUILDKITE_JOB_ID}
