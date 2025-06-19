#!/usr/bin/env bash
set -euo pipefail

function ess_up() {
  echo "~~~ Starting ESS Stack"
  local STACK_VERSION=$1
  local ESS_REGION=${2:-"gcp-us-west2"}
    
  if [ -z "$STACK_VERSION" ]; then
    echo "Error: Specify stack version: ess_up [stack_version]" >&2
    return 1
  fi

  oblt-cli
}

function ess_down() {
  echo "~~~ Tearing down the ESS Stack"  
  oblt-cli
}
