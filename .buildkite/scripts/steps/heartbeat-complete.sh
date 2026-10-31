#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

buildkite-agent artifact download 'build/distributions/elastic-agent-complete-*-linux-amd64.docker.tar.gz' . --step 'packaging-containers-amd64'

shopt -s nullglob

# load_image loads the Docker archive matching the pattern and prints its image tag.
load_image() {
  local archives=($1)
  if [[ "${#archives[@]}" -eq 0 ]]; then
    echo "Error: no Docker archive matching $1" >&2
    exit 1
  fi
  echo "Using Docker archive: ${archives[0]}" >&2
  docker load -i "${archives[0]}" >&2
  tar -xOf "${archives[0]}" manifest.json | jq -er '.[0].RepoTags[0]'
}

ELASTIC_AGENT_COMPLETE_IMAGE="$(load_image 'build/distributions/elastic-agent-complete-[0-9]*-linux-amd64.docker.tar.gz')"
ELASTIC_AGENT_COMPLETE_WOLFI_IMAGE="$(load_image 'build/distributions/elastic-agent-complete-wolfi-*-linux-amd64.docker.tar.gz')"
export ELASTIC_AGENT_COMPLETE_IMAGE ELASTIC_AGENT_COMPLETE_WOLFI_IMAGE

.buildkite/scripts/steps/integration_tests_oblt-cli.sh heartbeat-complete true
