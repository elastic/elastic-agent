#!/usr/bin/env bash

set -euo pipefail

source .buildkite/scripts/common.sh

docker run -d --rm \
  -p 3000:3000 \
  -e ATHENS_STORAGE_TYPE=memory \
  -e ATHENS_GOGET_STORAGE_TYPE=memory \
  --name athens-proxy \
  gomods/athens:latest