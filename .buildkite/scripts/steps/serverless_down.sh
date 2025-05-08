#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common2.sh
source .buildkite/scripts/steps/serverless.sh

serverless_down || echo "Failed to unprovision the Serverless Observability project" >&2
