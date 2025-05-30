#!/usr/bin/env bash

set -euo pipefail

export DELETE_CREATED_AFTER_DATE=$(date -Is -d "5 hours ago")

docker run -v $(pwd)/.buildkite/misc/gce-cleanup.yml:/etc/cloud-reaper/config.yml \
  -e ACCOUNT_SECRET="$ACCOUNT_SECRET" \
  -e ACCOUNT_KEY="$ACCOUNT_KEY_SECRET" \
  -e ACCOUNT_PROJECT=$ACCOUNT_PROJECT_SECRET \
  -e DELETE_CREATED_AFTER_DATE=$DELETE_CREATED_AFTER_DATE \
  ${DOCKER_REGISTRY}/observability-ci/cloud-reaper:0.3.0 cloud-reaper --config /etc/cloud-reaper/config.yml destroy --confirm
