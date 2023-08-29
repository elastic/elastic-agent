#!/usr/bin/env bash

set -euo pipefail

export ACCOUNT_KEY_SECRET=$(vault kv get -field=client_email $VAULT_PATH)
export ACCOUNT_SECRET=$(vault kv get -field=private_key $VAULT_PATH)
export ACCOUNT_PROJECT_SECRET=$(vault kv get -field=project_id $VAULT_PATH)
export CREATION_DATE=$(date -Is -d "24 hours ago")

docker run -v $(pwd)/.buildkite/misc/gce-cleanup.yml:/etc/cloud-reaper/config.yml \
  -e ACCOUNT_SECRET="$ACCOUNT_SECRET" \
  -e ACCOUNT_KEY="$ACCOUNT_KEY_SECRET" \
  -e ACCOUNT_PROJECT=$ACCOUNT_PROJECT_SECRET \
  -e CREATION_DATE=$CREATION_DATE \
  ${DOCKER_REGISTRY}/observability-ci/cloud-reaper:0.3.0 cloud-reaper --config /etc/cloud-reaper/config.yml destroy --confirm
