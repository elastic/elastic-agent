#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh

source .buildkite/scripts/steps/ess.sh

ess_down || echo "Failed to stop ESS stack" >&2
