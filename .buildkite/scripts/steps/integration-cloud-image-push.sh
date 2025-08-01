#!/usr/bin/env bash
set -euo pipefail

source .buildkite/scripts/common.sh

echo "~~~ Pushing cloud image"

suffix=""
if [ "${FIPS:-false}" == "true" ]; then
  suffix="-fips"
fi

CI_ELASTIC_AGENT_DOCKER_IMAGE="docker.elastic.co/beats-ci/elastic-agent-cloud${suffix}"
export CI_ELASTIC_AGENT_DOCKER_IMAGE
echo "CI_ELASTIC_AGENT_DOCKER_IMAGE: ${CI_ELASTIC_AGENT_DOCKER_IMAGE}"


export CUSTOM_IMAGE_TAG="git-${BUILDKITE_COMMIT:0:12}"
export USE_PACKAGE_VERSION="true"

mage cloud:push
