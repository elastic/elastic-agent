#!/usr/bin/env bash

# ELASTICSEARCH CONFIDENTIAL
# __________________
#
#  Copyright Elasticsearch B.V. All rights reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of Elasticsearch B.V. and its suppliers, if any.
# The intellectual and technical concepts contained herein
# are proprietary to Elasticsearch B.V. and its suppliers and
# may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright
# law.  Dissemination of this information or reproduction of
# this material is strictly forbidden unless prior written
# permission is obtained from Elasticsearch B.V.

set -eox pipefail

_SELF=$(dirname $0)
source "${_SELF}/../common.sh"

setup_extract_sha() {
    # Ensure repo is available - redirect output to /dev/null
    if [ ! -d "serverless-gitops" ]; then
        git clone --depth 1 git@github.com:elastic/serverless-gitops.git
    else
        (cd serverless-gitops && git pull)
    fi

    # Install yq for YAML parsing
    go install github.com/mikefarah/yq/v4@v4.45.1
}

extract_sha() {
    local env=$1
    
    # Extract first matching SHA for the environment pattern
    yq eval ".services.agentless-controller.versions | to_entries | .[] | select(.key | test(\"^${env}.*\")) | .value" serverless-gitops/services/agentless-controller/versions.yaml | head -1
}


# Check environment variable
if [ -z "${ENVIRONMENT:-}" ]; then
    echo "ENVIRONMENT variable is not set"
    exit 1
fi

setup_extract_sha

# Extract agentless_controller_sha for the specified environment
agentless_controller_sha=$(extract_sha "$ENVIRONMENT")

if [ -z "$agentless_controller_sha" ]; then
    echo "No SHA found for environment: $ENVIRONMENT"
    exit 1
fi

echo "Running agentless tests for environment $ENVIRONMENT with Agentless-Controller version: $agentless_controller_sha"
export SERVICE_VERSION="$agentless_controller_sha"
make -C /agent run-environment-tests # part of docker.elastic.co/ci-agent-images/quality-gate-seedling image
