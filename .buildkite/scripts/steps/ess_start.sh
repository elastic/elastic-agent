#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common-integration.sh
source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

echo "~~~ Getting stable stack version"
mage -v integration:getStableEssSnapshotForBranch
OVERRIDE_STACK_VERSION="$(cat .override_stack_version)-SNAPSHOT"

ess_up $OVERRIDE_STACK_VERSION

preinstall_fleet_packages

echo "ES_HOST: ${ELASTICSEARCH_HOST}"
buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST
buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME
buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD
buildkite-agent meta-data set "kibana.host" $KIBANA_HOST
buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME
buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD
