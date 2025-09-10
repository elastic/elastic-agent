#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/steps/ess.sh

ESS_REGION="${ESS_REGION:-gcp-us-west2}"

ess_down "$ESS_REGION"