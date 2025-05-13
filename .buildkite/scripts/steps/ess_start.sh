#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common-integration.sh
source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

DEFAULT_STACK_VERSION="$(cat .package-version)-SNAPSHOT"
STABLE_SNAPSHOT_VERSION="$(cat .stable-snapshot-version)-SNAPSHOT"
ess_up $DEFAULT_STACK_VERSION $STABLE_SNAPSHOT_VERSION

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD
