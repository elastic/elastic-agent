#!/usr/bin/env bash
set -euo pipefail
source .buildkite/scripts/steps/stable_ess_version.sh
source .buildkite/scripts/common-integration.sh
source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

echo "~~~ Getting stable stack version"
DEFAULT_STACK_VERSION="$(cat .package-version)-SNAPSHOT"
STABLE_ESS_VERSION="$(getStableEssSnapshotForBranch)-SNAPSHOT"
ess_up $DEFAULT_STACK_VERSION $STABLE_STACK_VERSION
echo "ES_HOST: ${ELASTICSEARCH_HOST}"

preinstall_fleet_packages

if [ "${CI:=false}" == 'true' ]; then  
  buildkite-agent meta-data set "es.host" $ELASTICSEARCH_HOST
  buildkite-agent meta-data set "es.username" $ELASTICSEARCH_USERNAME
  buildkite-agent meta-data set "es.pwd" $ELASTICSEARCH_PASSWORD
  buildkite-agent meta-data set "kibana.host" $KIBANA_HOST
  buildkite-agent meta-data set "kibana.username" $KIBANA_USERNAME
  buildkite-agent meta-data set "kibana.pwd" $KIBANA_PASSWORD

  buildkite-agent meta-data set "stable.ess.version" $STABLE_ESS_VERSION
fi