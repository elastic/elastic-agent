#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

ess_up $OVERRIDE_STACK_VERSION || echo "Failed to start ESS stack" >&2

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD
