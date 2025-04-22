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

preinstall_fleet_packages
