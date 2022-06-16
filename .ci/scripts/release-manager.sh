#!/usr/bin/env bash
#
# This script is executed by the daily release artifact stage.
# It requires the below environment variables:
# - BRANCH_NAME
# - VAULT_ADDR
# - VAULT_ROLE_ID
# - VAULT_SECRET_ID
#
set -uexo pipefail

source /usr/local/bin/bash_standard_lib.sh

# set required permissions on artifacts and directory
chmod -R a+r build/distributions/*
chmod -R a+w build/distributions

# get the current version (without the snapshot)
VERSION=$(make get-version)

# ensure the latest image has been pulled
IMAGE=docker.elastic.co/infra/release-manager:latest
(retry 3 docker pull --quiet "${IMAGE}") || echo "Error pulling ${IMAGE} Docker image, we continue"
docker images --filter=reference=$IMAGE

# Generate checksum files and upload to GCS
docker run --rm \
  --name release-manager \
  -e VAULT_ADDR \
  -e VAULT_ROLE_ID \
  -e VAULT_SECRET_ID \
  --mount type=bind,readonly=false,src="$PWD",target=/artifacts \
  "$IMAGE" \
    cli collect \
      --project elastic-agent \
      --branch "main" \
      --commit "$(git rev-parse HEAD)" \
      --workflow "snapshot" \
      --artifact-set main \
      --version "${VERSION}"
