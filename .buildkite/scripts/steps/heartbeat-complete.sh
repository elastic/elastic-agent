#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

archive_pattern='build/distributions/elastic-agent-complete-*-linux-amd64.docker.tar.gz'
buildkite-agent artifact download "$archive_pattern" . --step 'packaging-containers-amd64'

shopt -s nullglob
archives=($archive_pattern)
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "Error: no complete Docker archive found" >&2
  exit 1
fi

archive="${archives[0]}"
echo "Using complete Docker archive: $archive"
export ELASTIC_AGENT_COMPLETE_IMAGE="$(tar -xOf "$archive" manifest.json | jq -er '.[0].RepoTags[0]')"
docker load -i "$archive"

.buildkite/scripts/steps/integration_tests_oblt-cli.sh heartbeat-complete true
