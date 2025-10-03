#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh


ATHENS_IP=$(ip route get 1 | awk '{print $7; exit}')

buildkite-agent meta-data set "athens-proxy" "http://$ATHENS_IP:3000"

docker run -d --rm \
  -p 3000:3000 \
  -e ATHENS_STORAGE_TYPE=memory \
  -e ATHENS_GOGET_STORAGE_TYPE=memory \
  --name athens-proxy \
  gomods/athens:latest

go mod download

sleep 1h