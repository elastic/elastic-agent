#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

# Parsing version.go. Will be simplified here: https://github.com/elastic/ingest-dev/issues/4925
STACK_VERSION=$(grep "const defaultBeatVersion =" version/version.go | cut -d\" -f2)
STACK_VERSION="${STACK_VERSION}-SNAPSHOT"

ess_up $STACK_VERSION

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD
