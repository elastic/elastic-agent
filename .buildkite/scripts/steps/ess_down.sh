#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

OVERRIDE_AGENT_PACKAGE_VERSION="$(cat .package-version)"
OVERRIDE_TEST_AGENT_VERSION=${OVERRIDE_AGENT_PACKAGE_VERSION}"-SNAPSHOT"

ess_down || echo "Failed to stop ESS stack" >&2
