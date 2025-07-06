#!/usr/bin/env bash
#
# This script initializes and starts the ESS environment for testing.
# It performs the following steps:
#   1. Sources helper scripts for ESS and Fleet operations.
#   2. Reads the stack version from the .package-version file and appends "-SNAPSHOT".
#   3. Starts the ESS stack with the specified version.
#   4. Pre-installs required Fleet packages.
# Usage: Intended to be run as part of the Buildkite CI pipeline.
#

set -euo pipefail

source .buildkite/scripts/steps/ess.sh
source .buildkite/scripts/steps/fleet.sh

OVERRIDE_STACK_VERSION="$(cat .package-version)"
OVERRIDE_STACK_VERSION=${OVERRIDE_STACK_VERSION}"-SNAPSHOT"

ess_up $OVERRIDE_STACK_VERSION

preinstall_fleet_packages
