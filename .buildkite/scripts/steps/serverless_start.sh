#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh
source .buildkite/scripts/steps/serverless.sh

serverless_up

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set "serverless.es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "serverless.es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "serverless.es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "serverless.kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "serverless.kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "serverless.kibana.pwd" $KIBANA_PASSWORD
