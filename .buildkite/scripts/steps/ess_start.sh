#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

STACK_VERSION="$(jq -r '.version' .package-version)"
STACK_BUILD_ID="$(jq -r '.stack_build_id' .package-version)"

ess_up "$STACK_VERSION" "$STACK_BUILD_ID"

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set --redacted-vars='' "es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set --redacted-vars='' "es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set --redacted-vars='' "es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set --redacted-vars='' "kibana.host" $KIBANA_HOST
buildkite-agent meta-data set --redacted-vars='' "kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set --redacted-vars='' "kibana.pwd" $KIBANA_PASSWORD
